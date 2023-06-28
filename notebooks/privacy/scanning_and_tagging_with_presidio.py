# Databricks notebook source
# MAGIC %run ../../common/install_libs

# COMMAND ----------

# MAGIC %run ../../common/functions

# COMMAND ----------

all_catalogs = list(filter(None, [x[0] for x in sql("SHOW CATALOGS").collect()]))
catalogs = all_catalogs.copy()
catalogs.insert(0, "ALL")

# See https://microsoft.github.io/presidio/supported_entities/ 
all_supported_entities = ["CREDIT_CARD", "CRYPTO", "DATE_TIME", "EMAIL_ADDRESS", "IBAN_CODE", "IP_ADDRESS", "NRP", "LOCATION", "PERSON", "PHONE_NUMBER", "MEDICAL_LICENSE", "URL", "US_BANK_NUMBER", "US_DRIVER_LICENSE", "US_ITIN", "US_PASSPORT", "US_SSN", "UK_NHS", "ES_NIF", "IT_FISCAL_CODE", "IT_DRIVER_LICENSE", "IT_VAT_CODE", "IT_PASSPORT", "IT_IDENTITY_CARD", "SG_NRIC_FIN", "AU_ABN", "AU_ACN", "AU_TFN", "AU_MEDICARE"]
supported_entities = all_supported_entities.copy()
supported_entities.insert(0, "ALL")

dbutils.widgets.multiselect(name="catalogs", defaultValue="ALL", choices=catalogs, label="catalogs_to_scan")
dbutils.widgets.multiselect(name="entities", defaultValue="ALL", choices=supported_entities, label="entities_to_detect")
dbutils.widgets.dropdown(name="sample_size", defaultValue="1000", choices=["100", "1000", "10000"], label="sample_size")
dbutils.widgets.dropdown(name="hit_rate", defaultValue="60", choices=["50", "60", "70", "80", "90"], label="hit_rate")
dbutils.widgets.dropdown(name="average_score", defaultValue="0.5", choices=["0.5", "0.6", "0.7", "0.8", "0.9"], label="average_score")
# To change the language you will need to download the relevant spacy model. See https://microsoft.github.io/presidio/analyzer/languages/
dbutils.widgets.dropdown(name="language", defaultValue="en", choices=["en"], label="language")

def get_selection(selection, all_options):

  if "ALL" in selection:
    return all_options
  else:
    return selection

# COMMAND ----------

CATALOGS = tuple(get_selection(selection=dbutils.widgets.get("catalogs").split(","), all_options=all_catalogs))
ENTITIES = get_selection(selection=dbutils.widgets.get("entities").split(","), all_options=all_supported_entities)
SAMPLE_SIZE = int(dbutils.widgets.get("sample_size"))

# To change the language you will need to download the relevant spacy model. See https://microsoft.github.io/presidio/analyzer/languages/
LANGUAGE = dbutils.widgets.get("language")

# Reduce false positives by narrowing down the list of entities and introducing a threshold on the confidence score...
HIT_RATE = int(dbutils.widgets.get("hit_rate"))
AVG_SCORE = float(dbutils.widgets.get("average_score"))

print(f"Scanning catalogs {CATALOGS} for PII entities {ENTITIES} using language {LANGUAGE} with a sample size of {SAMPLE_SIZE}. Filtering results based on a hit rate of {HIT_RATE} and an average score of {AVG_SCORE}...")

# COMMAND ----------

from pyspark.sql.functions import asc, col, when, lit

TABLES = (
  spark.sql(f"SELECT * FROM system.information_schema.tables WHERE table_catalog IN {CATALOGS}")
  .select("table_catalog", "table_schema", "table_name", when(col("table_type") == "VIEW", "VIEW").otherwise(lit("TABLE")).alias("table_type"), "created", "last_altered")
  .orderBy(col("table_catalog").asc(), col("table_schema").asc(), col("table_name").asc()))

display(TABLES)

# COMMAND ----------

from presidio_analyzer import AnalyzerEngine
from pyspark.sql.functions import pandas_udf
from pyspark.sql.types import StringType
import pandas as pd
import json

analyzer = AnalyzerEngine()

# broadcast the engines to the cluster nodes
broadcasted_analyzer = sc.broadcast(analyzer)

# define a pandas UDF function and a series function over it.
def analyze_text(text: str) -> str:
    analyzer = broadcasted_analyzer.value
    analyzer_results = analyzer.analyze(text=text, language=LANGUAGE, entities=ENTITIES)
    return json.dumps([x.to_dict() for x in analyzer_results]) 

def analyze_series(s: pd.Series) -> pd.Series:
    return s.astype(str).apply(analyze_text)

# define the function as pandas UDF
analyze = pandas_udf(analyze_series, returnType=StringType())

# COMMAND ----------

from pyspark.sql.types import ArrayType, StructType, StructField, IntegerType, DoubleType
from pyspark.sql.functions import from_json, transform

scan_schema = ArrayType(
  StructType([
    StructField("entity_type", StringType()),
    StructField("start", IntegerType()),
    StructField("end", IntegerType()),
    StructField("score", DoubleType())
  ]))

def scan_dataframe(input_df):

  input_df = input_df.limit(SAMPLE_SIZE).select([from_json(analyze(col(c).cast("string")), scan_schema).alias(c) for c in input_df.columns])

  return input_df

# COMMAND ----------

df = generate_fake_pii_data(num_rows=1000).select("customer_id", "name", "email", "ssn", "iban", "credit_card", "phone_number", "date_of_birth", "ipv4", "ipv6", "freetext")
display(df)

# COMMAND ----------

test_scan = df.transform(scan_dataframe)
display(test_scan)

# COMMAND ----------

from pyspark.sql.functions import explode, lit, mean, count

results_schema = StructType([
    StructField("column", StringType()),
    StructField("entity_type", StringType()),
    StructField("num_entities", DoubleType()),
    StructField("avg_score", DoubleType()),
    StructField("sample_size", IntegerType()),
    StructField("hit_rate", DoubleType()),
  ])

def get_aggregated_results(df):

  agg_df = spark.createDataFrame([], results_schema)

  for c in df.columns:

    exploded = df.select(lit(c).alias("column"), explode(col(c)).alias(c))

    new_df = (exploded.select(
      col("column"),
      col(f"{c}.entity_type"), 
      col(f"{c}.score")).groupBy("column", "entity_type")
    .agg(
      count("entity_type").alias("num_entities"),
      mean("score").alias("avg_score"))
    .withColumn("sample_size", lit(SAMPLE_SIZE))
    .withColumn("hit_rate", col("num_entities") / col("sample_size") * 100)
    .where(f"hit_rate >= {HIT_RATE} AND avg_score >= {AVG_SCORE}"))

    agg_df = agg_df.union(new_df)
    
  return agg_df

# COMMAND ----------

test_aggregated_results = test_scan.transform(get_aggregated_results)
display(test_aggregated_results)

# COMMAND ----------

from datetime import datetime

scanned_tables, tagged_tables, unscanned_tables, untagged_tables = [], [], [], []
today = datetime.today().strftime("%d/%m/%Y")
tables = TABLES.collect()

for t in tables:

  try:

    print(f"Scanning {t.table_catalog}.{t.table_schema}.{t.table_name} for PII")
    scanned = spark.table(f"{t.table_catalog}.{t.table_schema}.{t.table_name}").transform(scan_dataframe)
    aggregated_results = scanned.transform(get_aggregated_results).toPandas()
    scanned_tables.append(t)

    if len(aggregated_results) > 0:

      try:
        print(f"Adding PII tags to {t.table_catalog}.{t.table_schema}.{t.table_name}")
        sql(f"ALTER {t.table_type} {t.table_catalog}.{t.table_schema}.{t.table_name} SET TAGS ('PII')")

        if t.table_type == "TABLE":
          table_comment = f"""
> # WARNING! This table contains PII
> Table Scanned on {today}"""
          
          sql(f"COMMENT ON {t.table_type} {t.table_catalog}.{t.table_schema}.{t.table_name} IS '{table_comment}'")
        
        for index, value in aggregated_results["column"].drop_duplicates().items():

          result = aggregated_results[aggregated_results["column"] == value] 
          column_json = []

          for index, row in result.iterrows():
            
            sql(f"ALTER {t.table_type} {t.table_catalog}.{t.table_schema}.{t.table_name} SET TAGS ('{row.entity_type}')")
            column_json.append(row.to_json(indent=2))
            
          column_comment = f"""
'> ### WARNING! This column contains PII
```
{json.dumps(column_json)}
```
'"""
          sql(f"ALTER {t.table_type} {t.table_catalog}.{t.table_schema}.{t.table_name} ALTER COLUMN {row.column} COMMENT {column_comment}")

          if t.table_type == "TABLE":
            sql(f"ALTER {t.table_type} {t.table_catalog}.{t.table_schema}.{t.table_name} ALTER COLUMN {row.column} SET TAGS ('{row.entity_type}')")
        tagged_tables.append(t)

      except Exception as e:
        print(f"Unable to add PII tags to {t.table_catalog}.{t.table_schema}.{t.table_name} due to exception {e}")
        untagged_tables.append(t)

  except Exception as e:

    print(f"Unable to scan {t.table_catalog}.{t.table_schema}.{t.table_name} for PII due to exception {e}")
    unscanned_tables.append(t)

for t in unscanned_tables:

  try:

    print(f"Adding tag 'NOT_PII_SCANNED' to {t.table_catalog}.{t.table_schema}.{t.table_name}")
    if t.table_type == "TABLE":
      sql(f"ALTER {t.table_type} {t.table_catalog}.{t.table_schema}.{t.table_name} SET TAGS ('NOT_PII_SCANNED')")

  except Exception as e:

    print(f"Unable to add NOT_PII_SCANNED tags to {t.table_catalog}.{t.table_schema}.{t.table_name} due to exception {e}")
    untagged_tables.append(t)  

# COMMAND ----------

print(f"""
Scanned {len(scanned_tables)} of {len(tables)} tables for PII. 
Tagged {len(tagged_tables)} tables because they contained PII. 
Unable to scan {len(unscanned_tables)} tables.
Unable to tag {len(untagged_tables)} tables.
""")

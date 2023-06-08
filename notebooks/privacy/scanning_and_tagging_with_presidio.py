# Databricks notebook source
# MAGIC %run ../../common/presidio

# COMMAND ----------

CATALOGS = ["main", "aweaver"]
SAMPLE_SIZE = 1000
LANGUAGE = "en"

# Reduce false positives by narrowing down the list of entities and introducing a threshold on the confidence score...
ENTITIES = ["PERSON", "LOCATION", "NRP", "EMAIL_ADDRESS", "IP_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE", "US_SSN"] # See https://microsoft.github.io/presidio/supported_entities/ 
HIT_RATE = 60
AVG_SCORE = 0.50

# COMMAND ----------

from pyspark.sql.functions import asc, col

TABLES = None

if not CATALOGS:
  TABLES = spark.sql("SELECT * FROM system.information_schema.tables").select("table_catalog", "table_schema", "table_name").orderBy(col("table_catalog").asc(), col("table_schema").asc(), col("table_name").asc())
else:
  TABLES = TABLES = spark.sql(f"SELECT * FROM system.information_schema.tables WHERE table_catalog IN {tuple(CATALOGS)}").select("table_catalog", "table_schema", "table_name").orderBy(col("table_catalog").asc(), col("table_schema").asc(), col("table_name").asc())

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

    # if not analyzer_results:
    #   return None
    # else: 
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

  input_df = input_df.limit(SAMPLE_SIZE).select([from_json(analyze(col(c)), scan_schema).alias(c) for c in input_df.columns])

  return input_df

# COMMAND ----------

test_df = spark.table("diz.raw.fake_pii_data")

test_scan = test_df.transform(scan_dataframe)
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

test_results_pdf = test_aggregated_results.toPandas()

# COMMAND ----------

if len(test_results_pdf) > 0:
  for index, row in test_results_pdf.iterrows():
    print(f"{row.column} {row.entity_type} {row.num_entities} {row.avg_score} {row.sample_size} {row.hit_rate}") 

# COMMAND ----------

for t in TABLES.collect():

  try:
    print(f"Scanning {t.table_catalog}.{t.table_schema}.{t.table_name} for PII")
    scanned = spark.table(f"{t.table_catalog}.{t.table_schema}.{t.table_name}").transform(scan_dataframe)
    aggregated_results = scanned.transform(get_aggregated_results)
  except Exception as e:
    print(f"Unable to scan {t.table_catalog}.{t.table_schema}.{t.table_name} for PII due to exception {e}")

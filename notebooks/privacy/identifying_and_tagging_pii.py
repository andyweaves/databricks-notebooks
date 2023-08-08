# Databricks notebook source
# MAGIC %run ../../common/install_libs

# COMMAND ----------

# MAGIC %run ../../common/privacy_functions

# COMMAND ----------

all_catalogs = list(filter(None, [x[0] for x in sql("SHOW CATALOGS").limit(1000).collect()]))
catalogs = all_catalogs.copy()
catalogs.insert(0, "ALL")

supported_entities = all_supported_entities.copy()
supported_entities.insert(0, "ALL")

dbutils.widgets.multiselect(name="catalogs", defaultValue="ALL", choices=catalogs, label="catalogs_to_scan")
dbutils.widgets.multiselect(name="entities", defaultValue="ALL", choices=supported_entities, label="entities_to_detect")
dbutils.widgets.multiselect(name="language", defaultValue="en", choices=["en"], label="language")
  
catalogs = tuple(get_selection(selection=dbutils.widgets.get("catalogs").split(","), all_options=all_catalogs))
entities = get_selection(selection=dbutils.widgets.get("entities").split(","), all_options=all_supported_entities)
language = dbutils.widgets.get("language")

# COMMAND ----------

from presidio_analyzer import AnalyzerEngine

broadcasted_analyzer = sc.broadcast(AnalyzerEngine())

# In an ideal world we would define the UDFs in the class, but a Spark UDF can only be defined in a class as a static method...
def analyze_text(text: str) -> str:
    analyzer = broadcasted_analyzer.value
    analyzer_results = analyzer.analyze(text=text, entities=entities, language=language)
    return json.dumps([x.to_dict() for x in analyzer_results]) 

def analyze_series(s: pd.Series) -> pd.Series:
    return s.astype(str).apply(analyze_text)

analyze_udf = pandas_udf(analyze_series, returnType=StringType())

pii_scanner = PIIScanner(spark=spark, broadcasted_analyzer=broadcasted_analyzer, entities=entities, language=language,  sample_size=1000, average_score=0.5, hit_rate=60)

# COMMAND ----------

all_tables = pii_scanner.get_all_uc_tables(spark=spark, catalogs=catalogs).where("table_schema != 'information_schema'")
display(all_tables)

# COMMAND ----------

df = generate_fake_pii_data(num_rows=1000).select("customer_id", "name", "email", "ssn", "iban", "credit_card", "phone_number", "date_of_birth", "ipv4", "ipv6", "freetext")
display(df)

# COMMAND ----------

test_scan = df.transform(pii_scanner.scan_dataframe)
display(test_scan)

# COMMAND ----------

import os
import concurrent.futures

scan_results = pd.DataFrame()

with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:

  futures = [executor.submit(pii_scanner.scan_and_tag_securable, f"{securable.table_catalog}.{securable.table_schema}.{securable.table_name}", securable.table_type) for securable in all_tables.collect()]
  
  for future in concurrent.futures.as_completed(futures):

    result = future.result()
    if isinstance(result, pd.DataFrame):
      scan_results = pd.concat([scan_results, result])
    else:
      print(result)

# COMMAND ----------

display(scan_results)

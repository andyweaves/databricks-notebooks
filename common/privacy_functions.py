# Databricks notebook source
import pandas as pd
from typing import Iterator
from pyspark.sql.functions import pandas_udf, col, spark_partition_id, asc, create_map, array, lit
from pyspark.sql.types import *
import time
from datetime import date
import random
from faker import Faker
from mimesis import Generic
from mimesis.locales import Locale

schema = StructType([
  StructField("customer_id", LongType(), False),
  StructField("name", StringType(), False),
  StructField("email", StringType(), False),
  StructField("date_of_birth", DateType(), False),
  StructField("age", LongType(), False),
  StructField("address", StringType(), False),
  StructField("postcode", StringType(), False),
  StructField("ipv4", StringType(), False),
  StructField("ipv4_with_port", StringType(), False),
  StructField("ipv6", StringType(), False),
  StructField("mac_address", StringType(), False),
  StructField("phone_number", StringType(), False),
  StructField("ssn", StringType(), False),
  StructField("itin", StringType(), False),
  StructField("iban", StringType(), False),
  StructField("credit_card", LongType(), False),
  StructField("credit_card_with_spaces", StringType(), False),
  StructField("credit_card_full", StringType(), False),
  StructField("expiry_date", StringType(), False),
  StructField("security_code", StringType(), False),
  StructField("freetext", StringType(), False),
  StructField("passport", StringType(), False),
  StructField("aba", StringType(), False),
  StructField("bban", StringType(), False),
  StructField("uri", StringType(), False),
  StructField("url", StringType(), False),
  StructField("language", StringType(), False),
  StructField("nationality", StringType(), False),
  StructField("country", StringType(), False),
  StructField("date_time", StringType(), False),
  ])

fake = Faker("en_US")
generic = Generic(locale=Locale.EN)

def get_random_pii():
  return random.choice([fake.ascii_free_email(), fake.ipv4(), fake.ipv6()])

@pandas_udf("long")
def get_customer_id(batch_iter: Iterator[pd.Series]) -> Iterator[pd.Series]:
  for id in batch_iter:
      yield int(time.time()) + id

pii_struct_schema = StructType([
    StructField("email_address", StringType(), False),
    StructField("ipv4_private", StringType(), False),
    StructField("ip_address_v6", StringType(), False),
    StructField("ipv4_with_port", StringType(), False),
    StructField("mac", StringType(), False),
    StructField("imei", StringType(), False),
    StructField("credit_card_number", StringType(), False), 
    StructField("credit_card_expiration_date", StringType(), False), 
    StructField("cvv", StringType(), False), 
    StructField("paypal", StringType(), False), 
    StructField("random_text_with_email", StringType(), False),
    StructField("random_text_with_ipv4", StringType(), False)
])

def pii_struct():
  return (generic.person.email(), fake.ipv4_private(), fake.ipv6(), generic.internet.ip_v4_with_port(), generic.internet.mac_address(), generic.code.imei(), generic.payment.credit_card_number(), generic.payment.credit_card_expiration_date(), generic.payment.cvv(), generic.payment.paypal(), f"{fake.catch_phrase()} {generic.person.email()}", f"{fake.catch_phrase()} {fake.ipv4_public()}")

pii_struct_udf = udf(pii_struct, pii_struct_schema)

def generate_fake_data(pdf: pd.DataFrame) -> pd.DataFrame:
    
  def generate_data(y):
    
    dob = fake.date_between(start_date='-99y', end_date='-18y')

    y["name"] = fake.name()
    y["email"] = fake.ascii_free_email()
    y["date_of_birth"] = dob #.strftime("%Y-%m-%d")
    y["age"] = date.today().year - dob.year
    y["address"] = fake.address()
    y["ipv4"] = fake.ipv4()
    y["ipv4_with_port"] = generic.internet.ip_v4_with_port()
    y["ipv6"] = fake.ipv6()
    y["mac_address"] = fake.mac_address()
    y["postcode"] = fake.postcode()
    y["phone_number"] = fake.phone_number()
    y["ssn"] = fake.ssn()
    y["itin"] = fake.itin()
    y["iban"] = fake.iban()
    y["credit_card"] = int(fake.credit_card_number())
    y["credit_card_with_spaces"] = generic.payment.credit_card_number()
    y["credit_card_full"] = fake.credit_card_full()
    y["expiry_date"] = fake.credit_card_expire()
    y["security_code"] = fake.credit_card_security_code()
    y["freetext"] = f"{fake.sentence()} {get_random_pii()} {fake.sentence()} {get_random_pii()} {fake.sentence()}"
    y["passport"] = fake.passport_number()
    y["aba"] = fake.aba()
    y["bban"] = fake.bban()
    y["uri"] = fake.uri()
    y["url"] = fake.url()
    y["language"] = generic.person.language()
    y["nationality"] = generic.person.nationality()
    y["country"] = fake.country()
    y["date_time"] = fake.date_time().strftime("%c")

    return y
    
  return pdf.apply(generate_data, axis=1).drop(["partition_id", "id"], axis=1)

# COMMAND ----------

def generate_fake_pii_data(num_rows=1000):
  initial_data = spark.range(1, num_rows+1).withColumn("customer_id", get_customer_id(col("id"))) 
  return (
  initial_data
  .withColumn("partition_id", spark_partition_id())
  .groupBy("partition_id")
  .applyInPandas(generate_fake_data, schema)
  .withColumn("pii_struct", pii_struct_udf())
  .withColumn("pii_map", create_map(lit("email_address"), col("email"), lit("ip_address"), col("ipv4"), lit("home_address"), col("address"))) 
  .withColumn("pii_array", array("email", "ipv4", "ipv6"))
  .orderBy(asc("customer_id")))

# COMMAND ----------

def get_selection(selection: list, all_options: list) -> list:

  if "ALL" in selection:
    return all_options
  else:
    return selection

# COMMAND ----------

# See https://microsoft.github.io/presidio/supported_entities/ 

all_supported_entities = ["CREDIT_CARD", "CRYPTO", "DATE_TIME", "EMAIL_ADDRESS", "IBAN_CODE", "IP_ADDRESS", "NRP", "LOCATION", "PERSON", "PHONE_NUMBER", "MEDICAL_LICENSE", "URL", "US_BANK_NUMBER", "US_DRIVER_LICENSE", "US_ITIN", "US_PASSPORT", "US_SSN", "UK_NHS", "ES_NIF", "IT_FISCAL_CODE", "IT_DRIVER_LICENSE", "IT_VAT_CODE", "IT_PASSPORT", "IT_IDENTITY_CARD", "SG_NRIC_FIN", "AU_ABN", "AU_ACN", "AU_TFN", "AU_MEDICARE"]

# COMMAND ----------

from pyspark.sql import SparkSession, DataFrame
from pyspark.broadcast import Broadcast
from pyspark.sql.functions import asc, col, when, lit, from_json, explode, mean, count, pandas_udf
from pyspark.sql.types import StringType, ArrayType, StructType, StructField, IntegerType, DoubleType
import pandas as pd
import json
from datetime import date

class PIIScanner:

  def __init__(
    self, 
    spark: SparkSession, broadcasted_analyzer: Broadcast, entities: list, 
    language: str = "en",  sample_size: int = 1000, average_score: float = 0.5, hit_rate: int = 60):
      self.spark = spark 
      self.broadcasted_analyzer = broadcasted_analyzer
      self.entities = entities
      self.language = language
      self.sample_size = sample_size
      self.average_score = average_score
      self.hit_rate = hit_rate
      self.scan_schema = ArrayType(StructType([
        StructField("entity_type", StringType()),
        StructField("start", IntegerType()),
        StructField("end", IntegerType()),
        StructField("score", DoubleType())
      ]))
      self.results_schema = StructType([
        StructField("column", StringType()),
        StructField("entity_type", StringType()),
        StructField("num_entities", DoubleType()),
        StructField("avg_score", DoubleType()),
        StructField("sample_size", IntegerType()),
        StructField("hit_rate", DoubleType()),
    ])
      print(f"PII Scanner initialized using language {self.language.upper()}. Looking for entities {self.entities} with a sample size of {self.sample_size}, an average score of {self.average_score} and a hit rate of {self.hit_rate}.")

  @staticmethod
  def get_all_uc_tables(spark: SparkSession, catalogs: tuple) -> DataFrame:

    sql_clause = None
    print(f"Getting all uc tables in catalogs {', '.join(catalogs)}")
    if len(catalogs) == 1:
      sql_clause = f"table_catalog IN ('{catalogs[0]}')"
    else:
      sql_clause = f"table_catalog IN {catalogs}"
    return (
      spark.sql(f"SELECT * FROM system.information_schema.tables WHERE {sql_clause}")
      .select("table_catalog", 
              "table_schema", 
              "table_name",
              when(col("table_type") == "VIEW", "VIEW").otherwise(lit("TABLE")).alias("table_type"),
              "created", 
              "last_altered").
      orderBy(
        col("table_catalog").asc(), 
        col("table_schema").asc(), 
        col("table_name").asc()))

  def _get_aggregated_results(self, df: DataFrame) -> DataFrame:

    df_size = df.count()

    if df_size != self.sample_size:
      sample_size = df_size
    else:
      sample_size = self.sample_size
    results_df = spark.createDataFrame([], self.results_schema)

    for c in df.columns:
      
      exploded = df.select(lit(c).alias("column"), explode(col(c)).alias(c))
      new_df = (exploded.select(
        col("column"),
        col(f"{c}.entity_type"), 
        col(f"{c}.score")).groupBy("column", "entity_type")
                .agg(
                  count("entity_type").alias("num_entities"),
                  mean("score").alias("avg_score"))
                .withColumn("sample_size", lit(sample_size))
                .withColumn("hit_rate", col("num_entities") / col("sample_size") * 100)
                .where(f"hit_rate >= {self.hit_rate} AND avg_score >= {self.average_score}"))
      results_df = results_df.union(new_df)

    return results_df

  def _scan_dataframe(self, df: DataFrame) -> DataFrame:
    return (df.select([from_json(analyze_udf(col(c).cast("string")), self.scan_schema).alias(c) for c in df.columns]))

  def scan_dataframe(self, df: DataFrame) -> DataFrame:

    try:
      scanned = self._scan_dataframe(df).limit(self.sample_size)
      results = self._get_aggregated_results(scanned)

    except Exception as e:
      print(f"Failed to scan {securable_type} {securable_namespace} because of exception {e}")

    return results
  
  def add_tag(self, securable_namespace: str, securable_type: str, tag: str, column: str=None) -> None:

    sql_query, log_message = None, None
    if column:
      sql_query = f"ALTER {securable_type} {securable_namespace} ALTER COLUMN {column} SET TAGS ('{tag}')"
      log_message = f"Adding tag '{tag}' to column {column} on {securable_type} {securable_namespace}"
    else:
      sql_query = f"ALTER {securable_type} {securable_namespace} SET TAGS ('{tag}')"
      log_message = f"Adding tag '{tag}' to {securable_type} {securable_namespace}"
    
    try:
      print(log_message)
      self.spark.sql(sql_query)
    except Exception as e:
      print(f"Failed to add tag '{tag}' to {securable_type} {securable_namespace} because of exception {e}")

  def add_comment(self, securable_namespace: str, securable_type: str, comment: str, column: str=None) -> None:

    sql_query, log_message = None, None
    if column:
      sql_query = f"ALTER {securable_type} {securable_namespace} ALTER COLUMN {column} COMMENT '{comment}'"
      log_message = f"Adding comment to column {column} on {securable_type} {securable_namespace}"
    else:
      sql_query = f"COMMENT ON {securable_type} {securable_namespace} IS '{comment}'"
      log_message = f"Adding comment to {securable_type} {securable_namespace}"

    try:
      print(log_message)
      self.spark.sql(sql_query)
    
    except Exception as e:
      print(f"Failed to add comment to {securable_type} {securable_namespace} because of exception {e}")
  
  def _get_table_comment(self, date: date) -> str:

    return f"""> # `WARNING! This table contains PII`
# Table Scanned on `{date}`"""

  def _get_column_comment(self, column_json) -> str:

    return f"""> # WARNING! This column contains PII:
```
{json.dumps(column_json)}
```
"""

  def scan_and_tag_securable(self, securable_namespace: str, securable_type: str) -> DataFrame:

    today = date.today()
    print(f"Scanning {securable_type} {securable_namespace} for PII.")

    df = self.spark.table(securable_namespace).limit(self.sample_size)
    scanned = self._scan_dataframe(df)
    results = self._get_aggregated_results(scanned).toPandas()

    if len(results) > 0:

      self.add_tag(securable_namespace=securable_namespace, securable_type=securable_type, tag='PII')
      if securable_type == "TABLE":
        self.add_comment(securable_namespace=securable_namespace, securable_type=securable_type, comment=self._get_table_comment(today))

      for index, value in results["column"].drop_duplicates().items():

        result = results[results["column"] == value] 
        column_json = []

        for index, row in result.iterrows():
          self.add_tag(securable_namespace, securable_type, row.entity_type)
          column_json.append(row.to_json(indent=2))
          if securable_type == "TABLE":
            self.add_tag(securable_namespace=securable_namespace, securable_type=securable_type, tag=row.entity_type, column=row.column)
        if securable_type == "TABLE":
          self.add_comment(securable_namespace=securable_namespace, securable_type=securable_type, comment=self._get_column_comment(column_json), column=row.column)
    results.insert(0, "scan_date", today)
    results.insert(1, "securable", securable_namespace)
    return results

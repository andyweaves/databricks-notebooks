# Databricks notebook source
# MAGIC %run ../../common/generate_fake_pii

# COMMAND ----------

# MAGIC %sh
# MAGIC python -m spacy download en_core_web_lg > /databricks/driver/logs/spacy.log

# COMMAND ----------

df = generate_fake_pii_data(num_rows=10000).select("customer_id", "name", "email", "ssn", "iban", "credit_card", "phone_number", "date_of_birth", "ipv4", "ipv6")
display(df)

# COMMAND ----------

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from pyspark.sql.types import StringType
from pyspark.sql.functions import input_file_name, regexp_replace
from pyspark.sql.functions import col, pandas_udf
import pandas as pd
import os

anonymized_column = "phone_number" # name of column to anonymize
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# broadcast the engines to the cluster nodes
broadcasted_analyzer = sc.broadcast(analyzer)
broadcasted_anonymizer = sc.broadcast(anonymizer)

# define a pandas UDF function and a series function over it.
def anonymize_text(text: str) -> str:
    analyzer = broadcasted_analyzer.value
    anonymizer = broadcasted_anonymizer.value
    analyzer_results = analyzer.analyze(text=text, language="en")
    anonymized_results = anonymizer.anonymize(
        text=text,
        analyzer_results=analyzer_results
    )
    return anonymized_results.text


def anonymize_series(s: pd.Series) -> pd.Series:
    return s.astype(str).apply(anonymize_text)

# define the function as pandas UDF
anonymize = pandas_udf(anonymize_series, returnType=StringType())

# COMMAND ----------

# apply the udf to a single column
anonymized_df1 = df.withColumn(
   anonymized_column, anonymize(col(anonymized_column))
)

display(anonymized_df1.select("phone_number"))

# COMMAND ----------

df2 = df

# apply the udf to all columns
columns = df2.columns

for c in columns:
  print(f"Analyzing column '{c}'...")
  df2 = df2.withColumn(c, anonymize(col(c))
)

display(df2)

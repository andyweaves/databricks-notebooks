# Databricks notebook source
# MAGIC %run ../../common/generate_fake_pii

# COMMAND ----------

# MAGIC %sql
# MAGIC USE CATALOG diz

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE SCHEMA IF NOT EXISTS raw;
# MAGIC CREATE SCHEMA IF NOT EXISTS processed

# COMMAND ----------

df = generate_fake_pii_data(num_rows=1000).select("customer_id", "email", "phone_number", "postcode", "date_of_birth", "ipv4")
display(df)

# COMMAND ----------

df.write.mode("overwrite").saveAsTable("raw.fake_pii_data")

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE SCHEMA IF NOT EXISTS sysadmin

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE TABLE diz.sysadmin.token_lookup(token_type_id INT, token_type STRING)

# COMMAND ----------

# MAGIC %sql
# MAGIC INSERT INTO diz.sysadmin.token_lookup VALUES (2, "ipv4")

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM diz.sysadmin.token_lookup
# MAGIC ORDER BY token_type_id DESC

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE TABLE diz.processed.tokenized_pii_data (token_id INT, token_type_id INT, token_type STRING, token_value)

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT
# MAGIC customer_id,
# MAGIC regexp_replace(CAST(email AS STRING), '[\\w\\.=-]+@', '') AS email,
# MAGIC mask(phone_number, "X", "x", "*", " ") AS phone_number,
# MAGIC mask(postcode, "X", "x", "1", " ") AS postcode,
# MAGIC regexp_replace(date_of_birth, '(\\d{4})(-|/)(\\d{2})(-|/)(\\d{2})', 'YYYY-MM-DD') AS date_of_birth,
# MAGIC concat(substring_index(CAST(ipv4 AS STRING), '.', 3), '.0/24') AS ipv4
# MAGIC FROM diz.raw.fake_pii_data

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE TABLE diz.processed.tokenized_pii_data (id INT, name STRING, age INT)
# MAGIC     TBLPROPERTIES ('foo'='bar')
# MAGIC     COMMENT 'this is a comment';

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT
# MAGIC customer_id,
# MAGIC mask(phone_number, NULL, NULL, "0") AS phone_number
# MAGIC FROM diz.raw.fake_pii_data

# Databricks notebook source
# MAGIC %run ../common/generate_fake_pii

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
# MAGIC SELECT
# MAGIC customer_id,
# MAGIC mask(phone_number, NULL, NULL, "0") AS phone_number
# MAGIC FROM diz.raw.fake_pii_data

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT CAST(CAST(rand() AS INTEGER) AS STRING) AS ran

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
# MAGIC SELECT is_member('pii_viewer')

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE TABLE diz.processed.vw_fake_pii_data_redacted AS (
# MAGIC SELECT
# MAGIC customer_id,
# MAGIC CASE
# MAGIC   WHEN is_member('pii_viewers') THEN phone_number
# MAGIC     ELSE "[REDACTED]"
# MAGIC END AS phone_number
# MAGIC FROM diz.raw.fake_pii_data
# MAGIC )

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM diz.processed.vw_fake_pii_data_redacted

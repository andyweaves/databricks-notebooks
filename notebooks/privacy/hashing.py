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

import hashlib, uuid

salt = uuid.uuid4().hex
salt = dbutils.secrets.get("aweaver", "hash_salt")

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE TABLE diz.processed.fake_pii_data_hashed AS (
# MAGIC SELECT
# MAGIC customer_id,
# MAGIC sha2(concat(secret("aweaver", "hash_salt"), email), 256) AS email
# MAGIC FROM diz.raw.fake_pii_data
# MAGIC )

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT 
# MAGIC *
# MAGIC FROM diz.processed.fake_pii_data_hashed

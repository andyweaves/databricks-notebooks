# Databricks notebook source
# MAGIC %run ../../common/generate_fake_pii

# COMMAND ----------

df = generate_fake_pii_data(num_rows=10000).select("customer_id", "email", "phone_number", "postcode", "date_of_birth", "ipv4")
display(df)

# COMMAND ----------

df.createOrReplaceTempView("fake_pii_data")

# COMMAND ----------

import hashlib, uuid

salt = uuid.uuid4().hex
salt = dbutils.secrets.get("aweaver", "hash_salt")

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE SCHEMA IF NOT EXISTS main.temp

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE TABLE main.temp.hashed_pii_data AS (
# MAGIC SELECT
# MAGIC customer_id,
# MAGIC base64(unhex(sha2(concat(secret("aweaver", "hash_salt"), email), 256))) AS email
# MAGIC FROM fake_pii_data
# MAGIC )

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT 
# MAGIC *
# MAGIC FROM main.temp.hashed_pii_data

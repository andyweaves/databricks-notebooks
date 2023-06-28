# Databricks notebook source
# MAGIC %run ../../common/install_libs

# COMMAND ----------

# MAGIC %run ../../common/functions

# COMMAND ----------

df = generate_fake_pii_data(num_rows=1000).select("customer_id", "email", "phone_number", "postcode", "date_of_birth", "ipv4")
display(df)

# COMMAND ----------

df.write.mode("overwrite").saveAsTable("raw.fake_pii_data")

# COMMAND ----------

from base64 import b64encode
from os import urandom

#Generate a secret key
random_bytes = urandom(24)
secret_key = b64encode(random_bytes).decode('utf-8')

secret_key = dbutils.secrets.get("aweaver", "private_key")

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE TABLE diz.processed.fake_pii_data_encrypted AS (
# MAGIC SELECT
# MAGIC customer_id,
# MAGIC base64(aes_encrypt(email, secret("aweaver", "private_key"), 'GCM')) AS email,
# MAGIC base64(aes_encrypt(phone_number, secret("aweaver", "private_key"), 'GCM')) AS phone_number,
# MAGIC base64(aes_encrypt(postcode, secret("aweaver", "private_key"), 'GCM')) AS postcode,
# MAGIC base64(aes_encrypt(cast(date_of_birth AS STRING), secret("aweaver", "private_key"), 'GCM')) AS date_of_birth,
# MAGIC base64(aes_encrypt(ipv4, secret("aweaver", "private_key"), 'GCM')) AS ipv4
# MAGIC FROM diz.raw.fake_pii_data
# MAGIC )

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT 
# MAGIC customer_id,
# MAGIC cast(aes_decrypt(unbase64(email), secret("aweaver", "private_key"), 'GCM') AS STRING) AS email,
# MAGIC cast(aes_decrypt(unbase64(phone_number), secret("aweaver", "private_key"), 'GCM') AS STRING) AS phone_number,
# MAGIC cast(aes_decrypt(unbase64(postcode), secret("aweaver", "private_key"), 'GCM') AS STRING) AS postcode,
# MAGIC cast(aes_decrypt(unbase64(date_of_birth), secret("aweaver", "private_key"), 'GCM') AS STRING) AS date_of_birth,
# MAGIC cast(aes_decrypt(unbase64(ipv4), secret("aweaver", "private_key"), 'GCM') AS STRING) AS ipv4
# MAGIC FROM diz.processed.fake_pii_data_encrypted

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT is_member('pii_viewer')

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT is_member('pii_decrypter')

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE VIEW diz.processed.vw_fake_pii_data_encrypted AS (
# MAGIC   SELECT customer_id,
# MAGIC   CASE 
# MAGIC   WHEN is_member('pii_viewer') AND is_member('pii_admins') THEN cast(aes_decrypt(unbase64(email), secret("aweaver", "private_key"), 'GCM') AS STRING)
# MAGIC   WHEN is_member('pii_viewer') THEN regexp_replace(cast(aes_decrypt(unbase64(email), secret("aweaver", "private_key"), 'GCM') AS STRING), '[\\w\\.=-]+@', '')
# MAGIC     ELSE email
# MAGIC   END AS email
# MAGIC   FROM diz.processed.fake_pii_data_encrypted
# MAGIC )

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM diz.processed.vw_fake_pii_data_encrypted

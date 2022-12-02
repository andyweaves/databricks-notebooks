# Databricks notebook source
from base64 import b64encode
from os import urandom

random_bytes = urandom(24)
secret_key = b64encode(random_bytes).decode('utf-8')
secret_key

# COMMAND ----------

s = dbutils.secrets.get("aweaver", "2-2022")
s

# COMMAND ----------

# MAGIC %sql
# MAGIC SHOW TABLES IN aweaver

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM aweaver.iot_silver

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE TABLE aweaver.iot_encrypted AS (
# MAGIC     SELECT 
# MAGIC     timestamp,
# MAGIC     CONCAT(QUARTER(current_date()), "-", YEAR(current_date())) AS private_key,
# MAGIC     base64(aes_encrypt(ip, secret("aweaver", CONCAT(QUARTER(current_date()), "-", YEAR(current_date()))), 'GCM')) AS ip,
# MAGIC     cca2,
# MAGIC     cca3,
# MAGIC     cn,
# MAGIC     base64(aes_encrypt(cast(latitude AS STRING), secret("aweaver", CONCAT(QUARTER(current_date()), "-", YEAR(current_date()))), 'GCM')) AS latitude,
# MAGIC     base64(aes_encrypt(cast(longitude AS STRING), secret("aweaver", CONCAT(QUARTER(current_date()), "-", YEAR(current_date()))), 'GCM')) AS longitude,
# MAGIC     lcd,
# MAGIC     temp,
# MAGIC     scale,
# MAGIC     battery_level,
# MAGIC     c02_level
# MAGIC     FROM aweaver.iot_silver
# MAGIC )

# COMMAND ----------

# MAGIC 
# MAGIC %sql
# MAGIC --SELECT base64(aes_encrypt(ip, secret("aweaver", CONCAT(QUARTER(current_date()), "-", YEAR(current_date()))), 'GCM')) AS encrypted FROM aweaver.iot_silver

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT cast(aes_decrypt(unbase64("XmKCJ5OR+jAxljeey8VL58cv0aO2aLu9IQzWVw6liw9NUNUK50McqSg="), secret("aweaver", CONCAT(QUARTER(current_date()), "-", YEAR(current_date()))), 'GCM') AS STRING) AS decrypted --FROM aweaver.iot_silver

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM aweaver.iot_encrypted

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT 
# MAGIC     timestamp,
# MAGIC     private_key,
# MAGIC     CASE 
# MAGIC     WHEN private_key = "1-2022" THEN cast(aes_decrypt(unbase64(ip), secret("aweaver", "1-2022"), 'GCM') AS STRING) 
# MAGIC     WHEN  private_key = "4-2022" THEN cast(aes_decrypt(unbase64(ip), secret("aweaver", "4-2022"), 'GCM') AS STRING) 
# MAGIC     ELSE ip 
# MAGIC     END AS ip,
# MAGIC     cca2,
# MAGIC     cca3,
# MAGIC     cn,
# MAGIC     CASE 
# MAGIC     WHEN private_key = "1-2022" THEN cast(aes_decrypt(unbase64(latitude), secret("aweaver", "1-2022"), 'GCM') AS STRING) 
# MAGIC     WHEN  private_key = "4-2022" THEN cast(aes_decrypt(unbase64(latitude), secret("aweaver", "4-2022"), 'GCM') AS STRING) 
# MAGIC     ELSE latitude 
# MAGIC     END AS latitude,
# MAGIC     CASE 
# MAGIC     WHEN private_key = "1-2022" THEN cast(aes_decrypt(unbase64(longitude), secret("aweaver", "1-2022"), 'GCM') AS STRING) 
# MAGIC     WHEN  private_key = "4-2022" THEN cast(aes_decrypt(unbase64(longitude), secret("aweaver", "4-2022"), 'GCM') AS STRING) 
# MAGIC     ELSE longitude 
# MAGIC     END AS longitude,
# MAGIC     lcd,
# MAGIC     temp,
# MAGIC     scale,
# MAGIC     battery_level,
# MAGIC     c02_level
# MAGIC     FROM aweaver.iot_encrypted

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT CONCAT(QUARTER(current_date()), "-", YEAR(current_date())) AS secret

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM list_secrets();

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT cast(secret("aweaver", "secret_key") AS STRING) AS secret_key

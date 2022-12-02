# Databricks notebook source
from base64 import b64encode
from os import urandom

random_bytes = urandom(24)
secret_key = b64encode(random_bytes).decode('utf-8')
secret_key

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM list_secrets();

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT secret("aweaver", "secret_key") AS secret_key

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM customer_data

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE TABLE aweaver.customer_data_encrypted AS (
# MAGIC     SELECT 
# MAGIC     customer_id,
# MAGIC     CONCAT(QUARTER(current_date()), "-", YEAR(current_date())) AS private_key,
# MAGIC     base64(aes_encrypt(name, secret("aweaver", CONCAT(QUARTER(current_date()), "-", YEAR(current_date()))), 'GCM')) AS name,
# MAGIC     base64(aes_encrypt(email, secret("aweaver", CONCAT(QUARTER(current_date()), "-", YEAR(current_date()))), 'GCM')) AS email,
# MAGIC     base64(aes_encrypt(CAST(date_of_birth AS STRING), secret("aweaver", CONCAT(QUARTER(current_date()), "-", YEAR(current_date()))), 'GCM')) AS date_of_birth,
# MAGIC     base64(aes_encrypt(ipv4, secret("aweaver", CONCAT(QUARTER(current_date()), "-", YEAR(current_date()))), 'GCM')) AS ipv4,
# MAGIC     base64(aes_encrypt(ipv6, secret("aweaver", CONCAT(QUARTER(current_date()), "-", YEAR(current_date()))), 'GCM')) AS ipv6
# MAGIC     FROM customer_data
# MAGIC )

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM aweaver.customer_data_encrypted 

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM aweaver.customer_data_encrypted

# COMMAND ----------

import pandas as pd

new_data = [[9999999999, "3-2022", "John Smith", "john.smith@b.com", "01/01/1970", "192.168.0.1", "728a:27d6:f4c6:c290:b16d:9254:c03f:8a6e"]]

pdf = pd.DataFrame(new_data, columns = ["customer_id", "private_key", "name", "email", "date_of_birth", "ipv4", "ipv6"])
display(pdf)

# COMMAND ----------

df = spark.createDataFrame(pdf) 
df.write.mode("overwrite").saveAsTable("aweaver.customer_data_new")

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM aweaver.customer_data_new

# COMMAND ----------

# MAGIC %sql
# MAGIC INSERT INTO aweaver.customer_data_encrypted (
# MAGIC   SELECT 
# MAGIC     customer_id,
# MAGIC     private_key,
# MAGIC     base64(aes_encrypt(name, secret("aweaver", "3-2022"), 'GCM')) AS name,
# MAGIC     base64(aes_encrypt(email, secret("aweaver", "3-2022"), 'GCM')) AS email,
# MAGIC     base64(aes_encrypt(CAST(date_of_birth AS STRING), secret("aweaver", "3-2022"), 'GCM')) AS date_of_birth,
# MAGIC     base64(aes_encrypt(ipv4, secret("aweaver", "3-2022"), 'GCM')) AS ipv4,
# MAGIC     base64(aes_encrypt(ipv6, secret("aweaver", "3-2022"), 'GCM')) AS ipv6
# MAGIC     FROM aweaver.customer_data_new)

# COMMAND ----------

# MAGIC %sql
# MAGIC DROP TEMPORARY FUNCTION decrypt

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE TEMPORARY FUNCTION decrypt(col STRING, private_key STRING) RETURNS STRING 
# MAGIC RETURN (SELECT CASE 
# MAGIC WHEN private_key = CONCAT(QUARTER(current_date()), "-", YEAR(current_date())) 
# MAGIC THEN cast(aes_decrypt(unbase64(col), secret("aweaver", CONCAT(QUARTER(current_date()), "-", YEAR(current_date()))), 'GCM') AS STRING)
# MAGIC WHEN private_key = CONCAT(QUARTER(current_date()) - 1, "-", YEAR(current_date())) 
# MAGIC THEN cast(aes_decrypt(unbase64(col), secret("aweaver", CONCAT(QUARTER(current_date()) -1, "-", YEAR(current_date()))), 'GCM') AS STRING)
# MAGIC ELSE col
# MAGIC END);

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM aweaver.customer_data_encrypted WHERE customer_id = 9999999999

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT 
# MAGIC customer_id,
# MAGIC private_key,
# MAGIC decrypt(name, private_key) AS name,
# MAGIC date_of_birth,
# MAGIC ipv4
# MAGIC FROM
# MAGIC aweaver.customer_data_encrypted 

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT 
# MAGIC customer_id,
# MAGIC private_key,
# MAGIC decrypt(name, private_key) AS name,
# MAGIC date_of_birth,
# MAGIC ipv4
# MAGIC FROM
# MAGIC aweaver.customer_data_encrypted WHERE customer_id = 9999999999

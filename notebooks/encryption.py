# Databricks notebook source
# MAGIC %run ./generate_fake_pii

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE CATALOG IF NOT EXISTS production;
# MAGIC USE CATALOG production;
# MAGIC CREATE SCHEMA IF NOT EXISTS sales;
# MAGIC USE SCHEMA sales;

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1 - Generate a Private Key 
# MAGIC * Run the code below to generate a suitable string for an AES 256 private key

# COMMAND ----------

from base64 import b64encode
from os import urandom

random_bytes = urandom(24)
secret_key = b64encode(random_bytes).decode('utf-8')
secret_key

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2 - Create a Secret Scope
# MAGIC 
# MAGIC * Create a secret scope ([AWS](https://docs.databricks.com/security/secrets/secret-scopes.html) | [Azure](https://learn.microsoft.com/en-gb/azure/databricks/security/secrets/secret-scopes)) 
# MAGIC * Set Secret ACLs ([AWS](https://docs.databricks.com/security/access-control/secret-acl.html) | [Azure](https://learn.microsoft.com/en-gb/azure/databricks/security/access-control/secret-acl)) so that only members of a specific group can manage/access the secret scope

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 3 - Add the private key generated above to the Secret Scope
# MAGIC 
# MAGIC * Put the private key into a secret ([AWS](https://docs.databricks.com/security/secrets/secrets.html#create-a-secret) | [Azure](https://learn.microsoft.com/en-gb/azure/databricks/security/secrets/secrets#create-a-secret))
# MAGIC * Use the ```list_secrets()``` function to confirm that your secret is available for use 

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM list_secrets();

# COMMAND ----------

# MAGIC %md
# MAGIC * Confirm that the secret is ```[REDACTED]```

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT secret("aes_keys", "pii") AS secret

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 4 - Create functions to encrypt/decrypt the data

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION encrypt(col STRING) RETURNS STRING 
# MAGIC RETURN SELECT base64(aes_encrypt(col, secret("aes_keys", "pii"), 'GCM')) AS col

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION decrypt(col STRING) RETURNS STRING 
# MAGIC RETURN SELECT cast(aes_decrypt(unbase64(col), secret("aes_keys", "pii"), 'GCM') AS STRING) AS col

# COMMAND ----------

# MAGIC %sql
# MAGIC DESCRIBE FUNCTION EXTENDED decrypt

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 5 - Set Permissions
# MAGIC 
# MAGIC ![Securable objects in Unity Catalog](https://docs.databricks.com/_images/object-hierarchy.png)

# COMMAND ----------

# MAGIC %sql
# MAGIC GRANT USAGE ON CATALOG production to `pii_viewer`;
# MAGIC GRANT USAGE ON SCHEMA sales to `pii_viewer`;
# MAGIC GRANT EXECUTE ON FUNCTION decrypt TO `pii_viewer`;

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 6 - Create a table with encrypted data

# COMMAND ----------

# This needs to be run on a single user cluster
generate_fake_pii_data(num_rows=1000).select("customer_id", "email", "date_of_birth", "ssn", "phone_number").createOrReplaceTempView("tmp_vw_customers_raw")

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM tmp_vw_customers_raw

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE TABLE customer_data AS (
# MAGIC     SELECT 
# MAGIC     customer_id,
# MAGIC     encrypt(email) AS email, 
# MAGIC     encrypt(date_of_birth) AS date_of_birth,
# MAGIC     encrypt(ssn) AS ssn,
# MAGIC     encrypt(phone_number) AS phone_number
# MAGIC     FROM tmp_vw_customers_raw
# MAGIC )

# COMMAND ----------

# MAGIC %sql
# MAGIC DESCRIBE TABLE EXTENDED customer_data

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM production.sales.customer_data

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 7 - Create a view that allows members of the correct groups to be able to decrypt the data

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE VIEW vw_customer_data AS (
# MAGIC SELECT 
# MAGIC customer_id
# MAGIC customer_id,
# MAGIC CASE WHEN
# MAGIC     is_member('pii_viewer') THEN decrypt(email)
# MAGIC     ELSE email
# MAGIC   END AS email,
# MAGIC CASE WHEN
# MAGIC     is_member('pii_viewer') THEN decrypt(date_of_birth)
# MAGIC     ELSE date_of_birth
# MAGIC   END AS date_of_birth,
# MAGIC CASE WHEN
# MAGIC     is_member('pii_viewer') THEN decrypt(ssn)
# MAGIC     ELSE ssn
# MAGIC   END AS ssn,
# MAGIC CASE WHEN
# MAGIC     is_member('pii_viewer') THEN decrypt(phone_number)
# MAGIC     ELSE phone_number
# MAGIC   END AS phone_number
# MAGIC FROM customer_data
# MAGIC )

# COMMAND ----------

# MAGIC %sql
# MAGIC GRANT SELECT ON vw_customer_data TO `pii_viewer`

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT is_member('pii_viewer') AS should_i_see_pii

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM production.sales.vw_customer_data

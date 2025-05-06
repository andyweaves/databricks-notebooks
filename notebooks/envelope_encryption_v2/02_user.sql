-- Databricks notebook source
-- MAGIC %python
-- MAGIC dbutils.widgets.text(name="secret_scope", defaultValue="", label="The secret scope to use for DEKs")

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 1
-- MAGIC Check that the user is member of the `keyvault_user` group

-- COMMAND ----------

SELECT is_account_group_member('keyvault_user') AS is_keyvault_user

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 2
-- MAGIC Check that the user cannot access the raw data

-- COMMAND ----------

SELECT * FROM main.default.titanic_raw

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 3
-- MAGIC Check that the user cannot access the `sys.crypto.key_vault` catalog/schema/table 

-- COMMAND ----------

SHOW SCHEMAS IN sys

-- COMMAND ----------

SHOW TABLES IN sys.crypto

-- COMMAND ----------

SELECT * FROM sys.crypto.key_vault

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 4
-- MAGIC Check that the user cannot access any of the crypto functions

-- COMMAND ----------

SHOW FUNCTIONS IN sys.crypto

-- COMMAND ----------

SELECT sys.crypto.unwrap_key('key_to_unwrap', 'kek', 1) 

-- COMMAND ----------

DESCRIBE FUNCTION sys.crypto.unwrap_key

-- COMMAND ----------

SELECT sys.crypto.encrypt('text to encrypt') 

-- COMMAND ----------

DESCRIBE FUNCTION sys.crypto.encrypt

-- COMMAND ----------

SELECT sys.crypto.decrypt('text to decrypt')

-- COMMAND ----------

DESCRIBE FUNCTION sys.crypto.decrypt

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 5
-- MAGIC Check that the user can access the DEK and related secrets, but they `[REDACTED]` by default and encrypted when enumerated

-- COMMAND ----------

SELECT * FROM list_secrets() WHERE scope = :secret_scope

-- COMMAND ----------

SELECT SECRET(:secret_scope, 'dek') AS dek;

-- COMMAND ----------

-- MAGIC %python 
-- MAGIC # This will show either [REDACTED] or the encrypted DEK
-- MAGIC dek = dbutils.secrets.get(dbutils.widgets.get("secret_scope"), "dek")
-- MAGIC for c in dek:
-- MAGIC     print(dek)

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 6
-- MAGIC Check that the user can access the data

-- COMMAND ----------

SELECT * FROM main.default.titanic_encrypted

-- COMMAND ----------

DESCRIBE TABLE EXTENDED main.default.titanic_encrypted

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 7
-- MAGIC Remove membership of the `keyvault_user` group & check they can no longer access the decrypted data...

-- COMMAND ----------

-- Remove group membership, wait ~5 minutes and then check that it's been removed
CLEAR CACHE;
SELECT is_account_group_member('keyvault_user') AS is_keyvault_user;

-- COMMAND ----------

SELECT 
PassengerId,
Name,
Sex,
Age
FROM main.default.titanic_encrypted

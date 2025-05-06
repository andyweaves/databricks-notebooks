-- Databricks notebook source
-- MAGIC %python
-- MAGIC dbutils.widgets.text("schema", defaultValue="encrypted")
-- MAGIC dbutils.widgets.text("catalog", defaultValue="production")

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 1
-- MAGIC * Check whether the user is member of the relevant account level group

-- COMMAND ----------

SELECT is_account_group_member(concat(:catalog, '_', :schema, '_decrypt')) AS is_allowed_to_decrypt

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 2
-- MAGIC * Check that the user cannot access the raw data

-- COMMAND ----------

SELECT * 
FROM read_files(
  concat('/Volumes/', :catalog, '/', :schema, '/raw_files/titanic.csv'),
  format => 'csv',
  header => true,
  mode => 'FAILFAST');

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 3
-- MAGIC * Check that the user cannot view or access the `crypto` schema

-- COMMAND ----------

USE CATALOG IDENTIFIER(:catalog);
SHOW SCHEMAS

-- COMMAND ----------

SHOW TABLES IN IDENTIFIER(concat(:catalog, '.crypto'))

-- COMMAND ----------

SHOW FUNCTIONS IN IDENTIFIER(concat(:catalog, '.crypto'))

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 4
-- MAGIC * Check that the user cannot access any of the crypto functions

-- COMMAND ----------

DESCRIBE FUNCTION EXTENDED IDENTIFIER(concat(:catalog, '.crypto.unwrap_key'));

-- COMMAND ----------

SELECT * FROM (SELECT crypto.unwrap_key(concat('unity_catalog/', (element_at(split(current_metastore(), ':'), -1)), '/', :catalog), :schema))

-- COMMAND ----------

DESCRIBE FUNCTION EXTENDED IDENTIFIER(concat(:catalog, '.crypto.encrypt'));

-- COMMAND ----------

DESCRIBE FUNCTION EXTENDED IDENTIFIER(concat(:catalog, '.crypto.decrypt'));

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 4
-- MAGIC * Check whether the user can access the data

-- COMMAND ----------

SELECT *
FROM IDENTIFIER(:catalog || '.' || :schema || '.titanic');

-- COMMAND ----------

DESCRIBE TABLE EXTENDED IDENTIFIER(:catalog || '.' || :schema || '.titanic');

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 5
-- MAGIC * Now add the user to the the decrypt group, wait ~5 minutes for the groups to sync fully and then run the following command to check whether the user can decrypt the data. 
-- MAGIC * Optionally repeat the steps above to ensure that they still cannot access the crypto schema or functions 

-- COMMAND ----------

SELECT concat(:catalog, '_', :schema, '_decrypt') AS group_to_add_user_to

-- COMMAND ----------

SELECT is_account_group_member(concat(:catalog, '_', :schema, '_decrypt')) AS is_allowed_to_decrypt;

-- COMMAND ----------

SELECT *
FROM IDENTIFIER(:catalog || '.' || :schema || '.titanic');

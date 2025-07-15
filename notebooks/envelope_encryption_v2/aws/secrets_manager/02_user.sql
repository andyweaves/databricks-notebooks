-- Databricks notebook source
-- MAGIC %python
-- MAGIC dbutils.widgets.text("schema", defaultValue="human_resources")
-- MAGIC dbutils.widgets.text("catalog", defaultValue="production")
-- MAGIC dbutils.widgets.text("region", defaultValue="eu-west-1")
-- MAGIC dbutils.widgets.text("uc_service_credential", defaultValue="production-aws-secrets-manager")

-- COMMAND ----------

SELECT session_user() AS current_user

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 1
-- MAGIC * Check whether the user is member of the relevant account level group

-- COMMAND ----------

SELECT is_account_group_member(concat(:catalog, '.', :schema, '.crypto.user')) AS is_allowed_to_decrypt

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

-- COMMAND ----------

SHOW SCHEMAS;

-- COMMAND ----------

SHOW FUNCTIONS IN IDENTIFIER(concat(:catalog, '.crypto'))

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 4
-- MAGIC * Check that the user cannot access the UC service credential

-- COMMAND ----------

-- MAGIC %python
-- MAGIC import boto3
-- MAGIC
-- MAGIC boto3_session = boto3.Session(botocore_session=dbutils.credentials.getServiceCredentialsProvider(dbutils.widgets.get("uc_service_credential")), region_name=dbutils.widgets.get("region"))
-- MAGIC sm = boto3_session.client('secretsmanager')

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 5
-- MAGIC * Check that the user cannot access any of the crypto functions

-- COMMAND ----------

DESCRIBE FUNCTION EXTENDED IDENTIFIER(concat(:catalog, '.crypto.unwrap_key'));

-- COMMAND ----------

SELECT * FROM (SELECT crypto.unwrap_key(concat('unity_catalog/', (element_at(split(current_metastore(), ':'), -1)), '/', :catalog), :schema))

-- COMMAND ----------

DESCRIBE FUNCTION EXTENDED IDENTIFIER(concat(:catalog, '.crypto.encrypt'));

-- COMMAND ----------

SELECT crypto.encrypt("This is a string to encrypt", :schema) AS test 

-- COMMAND ----------

DESCRIBE FUNCTION EXTENDED IDENTIFIER(concat(:catalog, '.crypto.decrypt'));

-- COMMAND ----------

SELECT crypto.decrypt("R2RjeyuOoOsm4618FQA2lzXV1NHQ9plx5PSp+2X5k+COsX1aO9IOAt03uw0gKJ5bv3pNd9hNmA==", :schema) AS test 

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 6
-- MAGIC * Check whether the user can access the data

-- COMMAND ----------

SELECT *
FROM IDENTIFIER(:catalog || '.' || :schema || '.titanic');

-- COMMAND ----------

DESCRIBE TABLE EXTENDED IDENTIFIER(:catalog || '.' || :schema || '.titanic');

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Step 7
-- MAGIC * Now add the user to the the decrypt group, wait ~5 minutes for the groups to sync fully and then run the following command to check whether the user can decrypt the data. 
-- MAGIC * Optionally repeat the steps above to ensure that they still cannot access the crypto schema or functions 

-- COMMAND ----------

SELECT concat(:catalog, '.', :schema, '.crypto.user') AS group_to_add_user_to

-- COMMAND ----------

SELECT is_account_group_member(concat(:catalog, '.', :schema, '.crypto.user')) AS is_allowed_to_decrypt;

-- COMMAND ----------

SELECT *
FROM IDENTIFIER(:catalog || '.' || :schema || '.titanic');

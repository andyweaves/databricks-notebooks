# Databricks notebook source
dbutils.widgets.text(name="secret_scope", defaultValue="", label="The secret scope to use for DEKs")
dbutils.widgets.text(name="kek_name", defaultValue="", label="The name to use for our KEK")
dbutils.widgets.text(name="keyvault_user", defaultValue="", label="The username to grant unprivileged access to decrypt the data")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 1
# MAGIC Download some raw data that includes some non-sensitive personal information

# COMMAND ----------

# MAGIC %sh
# MAGIC wget https://raw.githubusercontent.com/datasciencedojo/datasets/master/titanic.csv -O /dbfs/titanic.csv

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE TABLE main.default.titanic_raw AS (SELECT * FROM read_files(
# MAGIC   'dbfs:/titanic.csv',
# MAGIC   format => 'csv',
# MAGIC   header => true,
# MAGIC   mode => 'FAILFAST'))

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM main.default.titanic_raw

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 2
# MAGIC Generate a Key Encryption Key (KEK) and create a `sys.keyvault.keys` table to store it in 

# COMMAND ----------

from base64 import b64encode
from os import urandom

kek = b64encode(urandom(24)).decode('utf-8')

# COMMAND ----------

# MAGIC %sql
# MAGIC --Create a keyvault catalog & schema
# MAGIC CREATE CATALOG IF NOT EXISTS sys;
# MAGIC CREATE SCHEMA IF NOT EXISTS sys.crypto;
# MAGIC
# MAGIC -- Create a row filter to additionally protect keys
# MAGIC CREATE OR REPLACE FUNCTION sys.crypto.key_vault_row_filter(managed_by STRING)
# MAGIC RETURN IF(is_account_group_member('keyvault_admin'), TRUE, managed_by=session_user());
# MAGIC
# MAGIC -- Create a column mask to additionally protect keys
# MAGIC CREATE OR REPLACE FUNCTION sys.crypto.key_vault_column_mask(key STRING)
# MAGIC RETURN CASE WHEN is_account_group_member('keyvault_admin') 
# MAGIC THEN key ELSE '[REDACTED]' END;
# MAGIC
# MAGIC -- Create a table for our keys
# MAGIC CREATE OR REPLACE TABLE sys.crypto.key_vault (
# MAGIC   id BIGINT GENERATED BY DEFAULT AS IDENTITY,
# MAGIC   created_date DATE, 
# MAGIC   created_time TIMESTAMP,
# MAGIC   last_modified_time TIMESTAMP,
# MAGIC   created_by STRING,
# MAGIC   managed_by STRING,
# MAGIC   key_name STRING,
# MAGIC   key_version INT,
# MAGIC   key_enabled BOOLEAN,
# MAGIC   key_type STRING,
# MAGIC   key STRING);
# MAGIC   -- Column mask / row filters break the decryption because user / group functions evaluate as the calling user
# MAGIC   -- key STRING MASK sys.crypto.key_vault_column_mask)
# MAGIC   -- WITH ROW FILTER sys.crypto.key_vault_row_filter ON (managed_by);

# COMMAND ----------

kek_name = dbutils.widgets.get("kek_name")

sql(f"""
    INSERT INTO sys.crypto.key_vault (created_date, created_time, last_modified_time, created_by, managed_by, key_name, key_version, key_enabled, key_type, key) 
    VALUES (current_date(), current_timestamp(), current_timestamp(), session_user(), session_user(), '{kek_name}', 1, True, 'KEK', '{kek}')""")

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM sys.crypto.key_vault

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 3
# MAGIC Use the KEK to encrypt our Data Encryption Key (DEK) and store the encrypted DEK as a secret (along with Initilisation Vector and Additionally Authenticated Data)

# COMMAND ----------

import string
import random

dek = b64encode(urandom(24)).decode('utf-8')
iv = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
aad = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

encrypted_dek = sql(f"SELECT base64(aes_encrypt('{dek}', '{kek}', 'GCM', 'DEFAULT'))").first()[0]
encrypted_iv = sql(f"SELECT base64(aes_encrypt('{iv}', '{kek}', 'GCM', 'DEFAULT'))").first()[0]
encrypted_aad = sql(f"SELECT base64(aes_encrypt('{aad}', '{kek}', 'GCM', 'DEFAULT'))").first()[0]

# COMMAND ----------

from databricks.sdk import WorkspaceClient

w = WorkspaceClient()

secret_scope = dbutils.widgets.get("secret_scope")

try:
    w.secrets.create_scope(scope=secret_scope)
except Exception as e:
    print(e)

w.secrets.put_secret(scope=secret_scope, key='dek', string_value=encrypted_dek)
w.secrets.put_secret(scope=secret_scope, key='iv', string_value=encrypted_iv)
w.secrets.put_secret(scope=secret_scope, key='aad', string_value=encrypted_aad)

display(sql(f"SELECT * FROM list_secrets() WHERE scope = '{secret_scope}'"))

# COMMAND ----------

from databricks.sdk.service import workspace

w.secrets.put_acl(scope=secret_scope, permission=workspace.AclPermission.READ, principal=dbutils.widgets.get("keyvault_user"))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 4
# MAGIC Create crypto functions to unwrap our keys and encrypt the data

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION sys.crypto.unwrap_key(key_to_unwrap STRING, key_to_use STRING) 
# MAGIC RETURNS STRING
# MAGIC RETURN aes_decrypt(unbase64(key_to_unwrap), (SELECT FIRST(key) FROM sys.crypto.key_vault WHERE key_enabled AND key_name = key_to_use), 'GCM', 'DEFAULT')

# COMMAND ----------

kek_name = dbutils.widgets.get("kek_name")

sql(f"""CREATE OR REPLACE FUNCTION sys.crypto.encrypt(col STRING) 
RETURNS STRING
RETURN 
    base64(aes_encrypt(col, 
    sys.crypto.unwrap_key(secret('{secret_scope}', 'dek'), '{kek_name}'),
    'GCM',  
    'DEFAULT',
    sys.crypto.unwrap_key(secret('{secret_scope}', 'iv'), '{kek_name}'),
    sys.crypto.unwrap_key(secret('{secret_scope}', 'aad'), '{kek_name}')
    ))""")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 5
# MAGIC Create a table with all of the personal information encrypted and grant access to our `keyvault_user`

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE TABLE main.default.titanic_encrypted AS (SELECT 
# MAGIC PassengerId,
# MAGIC Survived,
# MAGIC Pclass,
# MAGIC sys.crypto.encrypt(Name) AS Name,
# MAGIC sys.crypto.encrypt(Sex) AS Sex,
# MAGIC sys.crypto.encrypt(Age) AS Age,
# MAGIC SibSp,
# MAGIC Parch,
# MAGIC Ticket,
# MAGIC Fare,
# MAGIC Cabin,
# MAGIC Embarked
# MAGIC FROM main.default.titanic_raw)

# COMMAND ----------

sql(f"""GRANT SELECT ON main.default.titanic_encrypted TO `{dbutils.widgets.get("keyvault_user")}`""")

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT 
# MAGIC PassengerId,
# MAGIC Name,
# MAGIC Sex,
# MAGIC Age
# MAGIC FROM main.default.titanic_encrypted

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 6
# MAGIC Create a crypto function to decrypt the data

# COMMAND ----------

sql(f"""CREATE OR REPLACE FUNCTION sys.crypto.decrypt(col STRING) 
RETURNS STRING
RETURN 
    CASE WHEN is_account_group_member('keyvault_user') THEN 
    nvl(CAST(try_aes_decrypt(unbase64(col), 
    sys.crypto.unwrap_key(secret('{secret_scope}', 'dek'), '{kek_name}'),
    'GCM',  
    'DEFAULT',
    sys.crypto.unwrap_key(secret('{secret_scope}', 'aad'), '{kek_name}')) AS STRING), 
    col)
    ELSE col END;""")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 7
# MAGIC Apply the decrypt function as a column mask

# COMMAND ----------

# MAGIC %sql
# MAGIC ALTER TABLE main.default.titanic_encrypted ALTER COLUMN Name SET MASK sys.crypto.decrypt;
# MAGIC ALTER TABLE main.default.titanic_encrypted ALTER COLUMN Sex SET MASK sys.crypto.decrypt;
# MAGIC ALTER TABLE main.default.titanic_encrypted ALTER COLUMN Age SET MASK sys.crypto.decrypt

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 8
# MAGIC Query the data and confirm that the data is decryped as expected

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT 
# MAGIC PassengerId,
# MAGIC Name,
# MAGIC Sex,
# MAGIC Age
# MAGIC FROM main.default.titanic_encrypted

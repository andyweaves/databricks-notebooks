-- Databricks notebook source
-- MAGIC %md
-- MAGIC # AES Encrypt / Decrypt Table
-- MAGIC This notebook creates two stored procedures — `aes_encrypt_table()` and `aes_decrypt_table()` — that apply AES encryption or decryption across an entire table (or a specified subset of columns).
-- MAGIC
-- MAGIC **Key features:**
-- MAGIC - Encrypts/decrypts all columns or a user-specified list of columns
-- MAGIC - Works on tables, views, and temp views (i.e. DataFrames registered via `createOrReplaceTempView`)
-- MAGIC - Optionally writes results to a target table, or returns a result set
-- MAGIC - Generates a cryptographically random AES-256 key and stores it in Databricks Secrets (or use a pre-existing secret)
-- MAGIC - Uses `secret()` to retrieve the AES key from Databricks Secrets
-- MAGIC - Pure SQL procedures — callable from both SQL and PySpark

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 1: Setup — configure the catalog, schema and secret scope

-- COMMAND ----------

-- MAGIC %python 
-- MAGIC from databricks.sdk import WorkspaceClient
-- MAGIC import os
-- MAGIC
-- MAGIC ws = WorkspaceClient()
-- MAGIC
-- MAGIC catalogs = sorted([x.full_name for x in list(ws.catalogs.list())])
-- MAGIC dbutils.widgets.dropdown("catalog", defaultValue=catalogs[0], choices=catalogs[:1000], label="Catalog")
-- MAGIC schemas = [x.name for x in list(ws.schemas.list(catalog_name=dbutils.widgets.get("catalog")))]
-- MAGIC dbutils.widgets.dropdown("schema", defaultValue=schemas[0], choices=schemas[:1000], label="Schema")
-- MAGIC
-- MAGIC dbutils.widgets.text(name="secret_scope", defaultValue="", label="Secret Scope to use for DEK")
-- MAGIC dbutils.widgets.text(name="secret_key", defaultValue="", label="Secret Key to use for DEK")
-- MAGIC
-- MAGIC catalog = dbutils.widgets.get("catalog")
-- MAGIC schema = dbutils.widgets.get("schema")

-- COMMAND ----------

USE CATALOG IDENTIFIER(:catalog);
USE SCHEMA IDENTIFIER(:schema);
CREATE VOLUME IF NOT EXISTS IDENTIFIER(concat(:catalog, '.', :schema, '.raw_files'));

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 2: Generate an AES-256 key and store it as a Databricks Secret
-- MAGIC
-- MAGIC This generates a cryptographically random 256-bit AES key and stores it in the specified Databricks secret scope. The key is base64-encoded for safe storage as a string secret, and decoded back to binary at encrypt/decrypt time using `unbase64()`.
-- MAGIC
-- MAGIC > **Note:** The SQL `secret()` function always returns a STRING, so raw binary keys cannot be stored directly. Base64 encoding bridges this gap — the procedures use `unbase64(secret(...))` to recover the true binary key.
-- MAGIC
-- MAGIC If you already have a key in your secret scope, you can skip this step.

-- COMMAND ----------

-- MAGIC %python
-- MAGIC from databricks.sdk import WorkspaceClient
-- MAGIC from base64 import b64encode
-- MAGIC from os import urandom
-- MAGIC
-- MAGIC secret_scope = dbutils.widgets.get("secret_scope")
-- MAGIC secret_key = dbutils.widgets.get("secret_key")
-- MAGIC
-- MAGIC # Generate a cryptographically random 256-bit (32-byte) AES key, base64-encoded for storage
-- MAGIC aes_key_b64 = b64encode(urandom(32)).decode("utf-8")
-- MAGIC
-- MAGIC w = WorkspaceClient()
-- MAGIC
-- MAGIC # Create the secret scope if it doesn't already exist
-- MAGIC try:
-- MAGIC     w.secrets.create_scope(scope=secret_scope)
-- MAGIC     print(f"Created secret scope: {secret_scope}")
-- MAGIC except Exception as e:
-- MAGIC     print(f"Scope already exists or could not be created: {e}")
-- MAGIC
-- MAGIC # Store the base64-encoded key as a string secret
-- MAGIC w.secrets.put_secret(scope=secret_scope, key=secret_key, string_value=aes_key_b64)
-- MAGIC print(f"Stored AES-256 key in secret '{secret_scope}/{secret_key}'")

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 3: Get some fake PII data to demonstrate with
-- MAGIC * Download the titanic dataset and store it in a UC volume for raw files. 
-- MAGIC * We'll use this to simulate a dataset that contains PII (Name, Age, Sex)

-- COMMAND ----------

-- MAGIC %python
-- MAGIC import subprocess
-- MAGIC
-- MAGIC file_url = "https://raw.githubusercontent.com/datasciencedojo/datasets/master/titanic.csv"
-- MAGIC volume_path = f"/Volumes/{catalog}/{schema}/raw_files/titanic.csv"
-- MAGIC
-- MAGIC subprocess.run(["wget", file_url, "-O", volume_path], check=True)
-- MAGIC display(dbutils.fs.ls(f"/Volumes/{catalog}/{schema}/raw_files/"))

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 4: Create the `aes_encrypt_table` stored procedure
-- MAGIC
-- MAGIC **Parameters:**
-- MAGIC | Parameter | Type | Description |
-- MAGIC |---|---|---|
-- MAGIC | `source_table` | STRING | The source table, view, or temp view to read from |
-- MAGIC | `secret_scope` | STRING | The Databricks secret scope containing the AES key |
-- MAGIC | `secret_key` | STRING | The key name within the secret scope |
-- MAGIC | `columns_to_encrypt` | STRING | Comma-separated list of columns to encrypt, or `'*'` for all columns |
-- MAGIC | `target_table` | STRING | *(Optional)* If provided, writes results to this table. If empty, returns a result set |

-- COMMAND ----------

-- MAGIC %python
-- MAGIC spark.sql("""
-- MAGIC CREATE OR REPLACE PROCEDURE aes_encrypt_table(
-- MAGIC   source_table STRING,
-- MAGIC   secret_scope STRING,
-- MAGIC   secret_key STRING,
-- MAGIC   columns_to_encrypt STRING DEFAULT '*',
-- MAGIC   target_table STRING DEFAULT ''
-- MAGIC )
-- MAGIC LANGUAGE SQL
-- MAGIC SQL SECURITY INVOKER
-- MAGIC BEGIN
-- MAGIC   -- Build comma-separated list of columns to encrypt (or all columns if '*')
-- MAGIC   DECLARE encrypt_cols ARRAY<STRING>;
-- MAGIC   DECLARE all_cols ARRAY<STRING>;
-- MAGIC   DECLARE select_expr STRING DEFAULT '';
-- MAGIC   DECLARE i INT DEFAULT 0;
-- MAGIC   DECLARE col_name STRING;
-- MAGIC
-- MAGIC   -- Get all column names from the source table
-- MAGIC   SET all_cols = (
-- MAGIC     SELECT collect_list(column_name)
-- MAGIC     FROM (
-- MAGIC       SELECT column_name
-- MAGIC       FROM system.information_schema.columns
-- MAGIC       WHERE concat_ws('.', table_catalog, table_schema, table_name) = source_table
-- MAGIC       ORDER BY ordinal_position
-- MAGIC     )
-- MAGIC   );
-- MAGIC
-- MAGIC   -- If the table wasn't found in information_schema (e.g. it's a temp view), use DESCRIBE
-- MAGIC   IF (all_cols IS NULL OR size(all_cols) = 0) THEN
-- MAGIC     EXECUTE IMMEDIATE ('SELECT collect_list(col_name) FROM (DESCRIBE TABLE ' || source_table || ')') INTO all_cols;
-- MAGIC   END IF;
-- MAGIC
-- MAGIC   -- Determine which columns to encrypt
-- MAGIC   IF (columns_to_encrypt = '*') THEN
-- MAGIC     SET encrypt_cols = all_cols;
-- MAGIC   ELSE
-- MAGIC     SET encrypt_cols = (SELECT collect_list(trim(value)) FROM (SELECT explode(split(columns_to_encrypt, ',')) AS value));
-- MAGIC   END IF;
-- MAGIC
-- MAGIC   -- Build the SELECT expression
-- MAGIC   SET i = 0;
-- MAGIC   WHILE i < size(all_cols) DO
-- MAGIC     SET col_name = all_cols[i];
-- MAGIC     IF (i > 0) THEN
-- MAGIC       SET select_expr = select_expr || ', ';
-- MAGIC     END IF;
-- MAGIC     IF (array_contains(encrypt_cols, col_name)) THEN
-- MAGIC       SET select_expr = select_expr || 'base64(aes_encrypt(CAST(' || col_name || ' AS STRING), unbase64(secret(' || quote(secret_scope) || ', ' || quote(secret_key) || ')), ' || quote('GCM') || ', ' || quote('DEFAULT') || ')) AS ' || col_name;
-- MAGIC     ELSE
-- MAGIC       SET select_expr = select_expr || col_name;
-- MAGIC     END IF;
-- MAGIC     SET i = i + 1;
-- MAGIC   END WHILE;
-- MAGIC
-- MAGIC   -- Execute the query
-- MAGIC   IF (target_table != '') THEN
-- MAGIC     EXECUTE IMMEDIATE ('CREATE OR REPLACE TABLE ' || target_table || ' AS SELECT ' || select_expr || ' FROM ' || source_table);
-- MAGIC   ELSE
-- MAGIC     EXECUTE IMMEDIATE ('SELECT ' || select_expr || ' FROM ' || source_table);
-- MAGIC   END IF;
-- MAGIC END
-- MAGIC """)

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 5: Create the `aes_decrypt_table` stored procedure
-- MAGIC
-- MAGIC **Parameters:**
-- MAGIC | Parameter | Type | Description |
-- MAGIC |---|---|---|
-- MAGIC | `source_table` | STRING | The source table, view, or temp view to read from |
-- MAGIC | `secret_scope` | STRING | The Databricks secret scope containing the AES key |
-- MAGIC | `secret_key` | STRING | The key name within the secret scope |
-- MAGIC | `columns_to_decrypt` | STRING | Comma-separated list of columns to decrypt, or `'*'` for all columns |
-- MAGIC | `target_table` | STRING | *(Optional)* If provided, writes results to this table. If empty, returns a result set |

-- COMMAND ----------

-- MAGIC %python
-- MAGIC spark.sql("""
-- MAGIC CREATE OR REPLACE PROCEDURE aes_decrypt_table(
-- MAGIC   source_table STRING,
-- MAGIC   secret_scope STRING,
-- MAGIC   secret_key STRING,
-- MAGIC   columns_to_decrypt STRING DEFAULT '*',
-- MAGIC   target_table STRING DEFAULT ''
-- MAGIC )
-- MAGIC LANGUAGE SQL
-- MAGIC SQL SECURITY INVOKER
-- MAGIC BEGIN
-- MAGIC   DECLARE decrypt_cols ARRAY<STRING>;
-- MAGIC   DECLARE all_cols ARRAY<STRING>;
-- MAGIC   DECLARE select_expr STRING DEFAULT '';
-- MAGIC   DECLARE i INT DEFAULT 0;
-- MAGIC   DECLARE col_name STRING;
-- MAGIC
-- MAGIC   -- Get all column names from the source table
-- MAGIC   SET all_cols = (
-- MAGIC     SELECT collect_list(column_name)
-- MAGIC     FROM (
-- MAGIC       SELECT column_name
-- MAGIC       FROM system.information_schema.columns
-- MAGIC       WHERE concat_ws('.', table_catalog, table_schema, table_name) = source_table
-- MAGIC       ORDER BY ordinal_position
-- MAGIC     )
-- MAGIC   );
-- MAGIC
-- MAGIC   -- Fallback for temp views
-- MAGIC   IF (all_cols IS NULL OR size(all_cols) = 0) THEN
-- MAGIC     EXECUTE IMMEDIATE ('SELECT collect_list(col_name) FROM (DESCRIBE TABLE ' || source_table || ')') INTO all_cols;
-- MAGIC   END IF;
-- MAGIC
-- MAGIC   -- Determine which columns to decrypt
-- MAGIC   IF (columns_to_decrypt = '*') THEN
-- MAGIC     SET decrypt_cols = all_cols;
-- MAGIC   ELSE
-- MAGIC     SET decrypt_cols = (SELECT collect_list(trim(value)) FROM (SELECT explode(split(columns_to_decrypt, ',')) AS value));
-- MAGIC   END IF;
-- MAGIC
-- MAGIC   -- Build the SELECT expression
-- MAGIC   SET i = 0;
-- MAGIC   WHILE i < size(all_cols) DO
-- MAGIC     SET col_name = all_cols[i];
-- MAGIC     IF (i > 0) THEN
-- MAGIC       SET select_expr = select_expr || ', ';
-- MAGIC     END IF;
-- MAGIC     IF (array_contains(decrypt_cols, col_name)) THEN
-- MAGIC       SET select_expr = select_expr || 'CAST(aes_decrypt(unbase64(' || col_name || '), unbase64(secret(' || quote(secret_scope) || ', ' || quote(secret_key) || ')), ' || quote('GCM') || ', ' || quote('DEFAULT') || ') AS STRING) AS ' || col_name;
-- MAGIC     ELSE
-- MAGIC       SET select_expr = select_expr || col_name;
-- MAGIC     END IF;
-- MAGIC     SET i = i + 1;
-- MAGIC   END WHILE;
-- MAGIC
-- MAGIC   -- Execute the query
-- MAGIC   IF (target_table != '') THEN
-- MAGIC     EXECUTE IMMEDIATE ('CREATE OR REPLACE TABLE ' || target_table || ' AS SELECT ' || select_expr || ' FROM ' || source_table);
-- MAGIC   ELSE
-- MAGIC     EXECUTE IMMEDIATE ('SELECT ' || select_expr || ' FROM ' || source_table);
-- MAGIC   END IF;
-- MAGIC END
-- MAGIC """)

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 6: Encrypt all columns of a table

-- COMMAND ----------

-- Load the titanic CSV from the volume into a table
CREATE OR REPLACE TABLE IDENTIFIER(:catalog || '.' || :schema || '.titanic_raw') AS
SELECT * FROM read_files(
  concat('/Volumes/', :catalog, '/', :schema, '/raw_files/titanic.csv'),
  format => 'csv',
  header => 'true'
);

-- Encrypt every column and write to a new table
CALL aes_encrypt_table(
  source_table => :catalog || '.' || :schema || '.titanic_raw',
  secret_scope => :secret_scope,
  secret_key => :secret_key,
  columns_to_encrypt => '*',
  target_table => :catalog || '.' || :schema || '.titanic_encrypted'
);

-- COMMAND ----------

SELECT * FROM titanic_encrypted

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 7: Decrypt all columns back and verify round-trip

-- COMMAND ----------

CALL aes_decrypt_table(
  source_table => :catalog || '.' || :schema || '.titanic_encrypted',
  secret_scope => :secret_scope,
  secret_key => :secret_key
);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 8: Encrypt only specific columns

-- COMMAND ----------

-- Only encrypt the sensitive columns, leaving customer_id in the clear
CALL aes_encrypt_table(
  source_table => :catalog || '.' || :schema || '.titanic_raw',
  secret_scope => :secret_scope,
  secret_key => :secret_key,
  columns_to_encrypt => 'Name,Sex,Age',
  target_table => :catalog || '.' || :schema || '.titanic_encrypted_pii_columns_only'
);

-- COMMAND ----------

SELECT * FROM titanic_encrypted_pii_columns_only

-- COMMAND ----------

-- Decrypt just the columns we encrypted
CALL aes_decrypt_table(
  source_table => :catalog || '.' || :schema || '.titanic_encrypted_pii_columns_only',
  secret_scope => :secret_scope,
  secret_key => :secret_key,
  columns_to_decrypt => '*'
);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 9: Use with a DataFrame (temp view)

-- COMMAND ----------

-- The temp view `fake_pii_df` was registered earlier from a PySpark DataFrame.
-- This demonstrates that the procedures work on temp views too.
CALL aes_encrypt_table(
  source_table => 'fake_pii_df',
  secret_scope => :secret_scope,
  secret_key => :secret_key,
  columns_to_encrypt => 'email,ssn'
);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 10: Call from PySpark
-- MAGIC
-- MAGIC The procedures are equally callable from PySpark using `spark.sql()`:
-- MAGIC
-- MAGIC ```python
-- MAGIC # Register any DataFrame as a temp view
-- MAGIC df.createOrReplaceTempView("my_data")
-- MAGIC
-- MAGIC # Encrypt specific columns and return as a DataFrame
-- MAGIC encrypted_df = spark.sql("""
-- MAGIC   CALL aes_encrypt_table(
-- MAGIC     source_table => 'my_data',
-- MAGIC     secret_scope => 'my_scope',
-- MAGIC     secret_key => 'my_key',
-- MAGIC     columns_to_encrypt => 'email,ssn,name'
-- MAGIC   )
-- MAGIC """)
-- MAGIC
-- MAGIC # Encrypt all columns and write to a table
-- MAGIC spark.sql("""
-- MAGIC   CALL aes_encrypt_table(
-- MAGIC     source_table => 'my_catalog.my_schema.my_table',
-- MAGIC     secret_scope => 'my_scope',
-- MAGIC     secret_key => 'my_key',
-- MAGIC     columns_to_encrypt => '*',
-- MAGIC     target_table => 'my_catalog.my_schema.my_table_encrypted'
-- MAGIC   )
-- MAGIC """)
-- MAGIC ```

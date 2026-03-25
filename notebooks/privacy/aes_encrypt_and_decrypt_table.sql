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
-- MAGIC scopes = sorted([s.name for s in ws.secrets.list_scopes()])
-- MAGIC dbutils.widgets.dropdown("secret_scope", defaultValue=scopes[0], choices=scopes, label="Secret Scope to use for DEK")
-- MAGIC dbutils.widgets.text(name="secret_key", defaultValue="", label="Secret Key to use for DEK")
-- MAGIC
-- MAGIC catalog = dbutils.widgets.get("catalog")
-- MAGIC schema = dbutils.widgets.get("schema")
-- MAGIC secret_scope = dbutils.widgets.get("secret_scope")
-- MAGIC secret_key = dbutils.widgets.get("secret_key")

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
-- MAGIC | `columns_to_encrypt` | ARRAY&lt;STRING&gt; | *(Optional)* Array of column names to encrypt. If `NULL` and no tags specified, encrypts all columns |
-- MAGIC | `tags` | ARRAY&lt;STRING&gt; | *(Optional)* Array of Unity Catalog column tag names — columns with any of these tags will be encrypted |
-- MAGIC | `target_table` | STRING | *(Optional)* If provided, writes results to this table. If empty, returns a result set |

-- COMMAND ----------

-- MAGIC %python
-- MAGIC spark.sql("""
-- MAGIC CREATE OR REPLACE PROCEDURE aes_encrypt_table(
-- MAGIC   source_table STRING,
-- MAGIC   secret_scope STRING,
-- MAGIC   secret_key STRING,
-- MAGIC   columns_to_encrypt ARRAY<STRING> DEFAULT NULL,
-- MAGIC   tags ARRAY<STRING> DEFAULT NULL,
-- MAGIC   target_table STRING DEFAULT ''
-- MAGIC )
-- MAGIC LANGUAGE SQL
-- MAGIC SQL SECURITY INVOKER
-- MAGIC COMMENT 'AES-encrypts columns of a table using a key stored in Databricks Secrets. Encrypts all columns by default, or a specified subset by name or Unity Catalog column tags. Optionally writes results to a target table (with tags copied from the source) or returns a result set.'
-- MAGIC BEGIN
-- MAGIC   DECLARE select_expr STRING;
-- MAGIC   DECLARE all_cols ARRAY<STRING>;
-- MAGIC   DECLARE encrypt_key STRING DEFAULT quote(secret_scope) || ', ' || quote(secret_key);
-- MAGIC   DECLARE full_table_name STRING;
-- MAGIC
-- MAGIC   -- Resolve source_table to a fully qualified 3-level namespace
-- MAGIC   SET full_table_name = CASE
-- MAGIC     WHEN source_table NOT LIKE '%.%' THEN current_catalog() || '.' || current_schema() || '.' || source_table
-- MAGIC     WHEN source_table NOT LIKE '%.%.%' THEN current_catalog() || '.' || source_table
-- MAGIC     ELSE source_table
-- MAGIC   END;
-- MAGIC
-- MAGIC   -- If tags are specified, resolve them to column names via column_tags
-- MAGIC   IF (tags IS NOT NULL) THEN
-- MAGIC     SET columns_to_encrypt = (
-- MAGIC       SELECT collect_set(ct.column_name)
-- MAGIC       FROM system.information_schema.column_tags ct
-- MAGIC       WHERE concat_ws('.', ct.catalog_name, ct.schema_name, ct.table_name) = full_table_name
-- MAGIC         AND array_contains(tags, ct.tag_name)
-- MAGIC     );
-- MAGIC   END IF;
-- MAGIC
-- MAGIC   -- Build the SELECT expression in a single set-based query using string_agg
-- MAGIC   SET select_expr = (
-- MAGIC     SELECT string_agg(
-- MAGIC       CASE
-- MAGIC         WHEN columns_to_encrypt IS NULL OR array_contains(columns_to_encrypt, column_name)
-- MAGIC         THEN 'CASE WHEN ' || column_name || ' IS NOT NULL THEN base64(aes_encrypt(CAST(' || column_name || ' AS STRING), unbase64(secret(' || encrypt_key || ')), ' || quote('GCM') || ', ' || quote('DEFAULT') || ')) END AS ' || column_name
-- MAGIC         ELSE column_name
-- MAGIC       END,
-- MAGIC       ', '
-- MAGIC     ) WITHIN GROUP (ORDER BY ordinal_position)
-- MAGIC     FROM system.information_schema.columns
-- MAGIC     WHERE concat_ws('.', table_catalog, table_schema, table_name) = full_table_name
-- MAGIC   );
-- MAGIC
-- MAGIC   -- Fallback for temp views (not in information_schema)
-- MAGIC   IF (select_expr IS NULL) THEN
-- MAGIC     EXECUTE IMMEDIATE ('SELECT collect_list(col_name) FROM (DESCRIBE TABLE ' || source_table || ')') INTO all_cols;
-- MAGIC     SET select_expr = (
-- MAGIC       SELECT string_agg(
-- MAGIC         CASE
-- MAGIC           WHEN columns_to_encrypt IS NULL OR array_contains(columns_to_encrypt, col)
-- MAGIC           THEN 'CASE WHEN ' || col || ' IS NOT NULL THEN base64(aes_encrypt(CAST(' || col || ' AS STRING), unbase64(secret(' || encrypt_key || ')), ' || quote('GCM') || ', ' || quote('DEFAULT') || ')) END AS ' || col
-- MAGIC           ELSE col
-- MAGIC         END,
-- MAGIC         ', '
-- MAGIC       )
-- MAGIC       FROM explode(all_cols) AS t(col)
-- MAGIC     );
-- MAGIC   END IF;
-- MAGIC
-- MAGIC   -- Execute the query
-- MAGIC   IF (target_table != '') THEN
-- MAGIC     EXECUTE IMMEDIATE ('CREATE OR REPLACE TABLE ' || target_table || ' AS SELECT ' || select_expr || ' FROM ' || source_table);
-- MAGIC     -- Copy column tags from source to target table so tag-based decryption works
-- MAGIC     FOR tag_row AS (
-- MAGIC       SELECT column_name, tag_name, tag_value
-- MAGIC       FROM system.information_schema.column_tags
-- MAGIC       WHERE concat_ws('.', catalog_name, schema_name, table_name) = full_table_name
-- MAGIC     )
-- MAGIC     DO
-- MAGIC       EXECUTE IMMEDIATE ('ALTER TABLE ' || target_table || ' ALTER COLUMN ' || tag_row.column_name || ' SET TAGS (' || quote(tag_row.tag_name) || ' = ' || quote(tag_row.tag_value) || ')');
-- MAGIC     END FOR;
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
-- MAGIC | `columns_to_decrypt` | ARRAY&lt;STRING&gt; | *(Optional)* Array of column names to decrypt. If `NULL` and no tags specified, decrypts all columns |
-- MAGIC | `tags` | ARRAY&lt;STRING&gt; | *(Optional)* Array of Unity Catalog column tag names — columns with any of these tags will be decrypted |
-- MAGIC | `target_table` | STRING | *(Optional)* If provided, writes results to this table. If empty, returns a result set |

-- COMMAND ----------

-- MAGIC %python
-- MAGIC spark.sql("""
-- MAGIC CREATE OR REPLACE PROCEDURE aes_decrypt_table(
-- MAGIC   source_table STRING,
-- MAGIC   secret_scope STRING,
-- MAGIC   secret_key STRING,
-- MAGIC   columns_to_decrypt ARRAY<STRING> DEFAULT NULL,
-- MAGIC   tags ARRAY<STRING> DEFAULT NULL,
-- MAGIC   target_table STRING DEFAULT ''
-- MAGIC )
-- MAGIC LANGUAGE SQL
-- MAGIC SQL SECURITY INVOKER
-- MAGIC COMMENT 'AES-decrypts columns of a table using a key stored in Databricks Secrets. Decrypts all columns by default, or a specified subset by name or Unity Catalog column tags. Uses error-tolerant decryption (try_aes_decrypt) so non-encrypted columns pass through unchanged.'
-- MAGIC BEGIN
-- MAGIC   DECLARE select_expr STRING;
-- MAGIC   DECLARE all_cols ARRAY<STRING>;
-- MAGIC   DECLARE decrypt_key STRING DEFAULT quote(secret_scope) || ', ' || quote(secret_key);
-- MAGIC   DECLARE full_table_name STRING;
-- MAGIC
-- MAGIC   -- Resolve source_table to a fully qualified 3-level namespace
-- MAGIC   SET full_table_name = CASE
-- MAGIC     WHEN source_table NOT LIKE '%.%' THEN current_catalog() || '.' || current_schema() || '.' || source_table
-- MAGIC     WHEN source_table NOT LIKE '%.%.%' THEN current_catalog() || '.' || source_table
-- MAGIC     ELSE source_table
-- MAGIC   END;
-- MAGIC
-- MAGIC   -- If tags are specified, resolve them to column names via column_tags
-- MAGIC   IF (tags IS NOT NULL) THEN
-- MAGIC     SET columns_to_decrypt = (
-- MAGIC       SELECT collect_set(ct.column_name)
-- MAGIC       FROM system.information_schema.column_tags ct
-- MAGIC       WHERE concat_ws('.', ct.catalog_name, ct.schema_name, ct.table_name) = full_table_name
-- MAGIC         AND array_contains(tags, ct.tag_name)
-- MAGIC     );
-- MAGIC   END IF;
-- MAGIC
-- MAGIC   -- Build the SELECT expression in a single set-based query using string_agg
-- MAGIC   SET select_expr = (
-- MAGIC     SELECT string_agg(
-- MAGIC       CASE
-- MAGIC         WHEN columns_to_decrypt IS NULL OR array_contains(columns_to_decrypt, column_name)
-- MAGIC         THEN 'COALESCE(CAST(try_aes_decrypt(try_to_binary(' || column_name || ', ' || quote('BASE64') || '), unbase64(secret(' || decrypt_key || ')), ' || quote('GCM') || ', ' || quote('DEFAULT') || ') AS STRING), ' || column_name || ') AS ' || column_name
-- MAGIC         ELSE column_name
-- MAGIC       END,
-- MAGIC       ', '
-- MAGIC     ) WITHIN GROUP (ORDER BY ordinal_position)
-- MAGIC     FROM system.information_schema.columns
-- MAGIC     WHERE concat_ws('.', table_catalog, table_schema, table_name) = full_table_name
-- MAGIC   );
-- MAGIC
-- MAGIC   -- Fallback for temp views (not in information_schema)
-- MAGIC   IF (select_expr IS NULL) THEN
-- MAGIC     EXECUTE IMMEDIATE ('SELECT collect_list(col_name) FROM (DESCRIBE TABLE ' || source_table || ')') INTO all_cols;
-- MAGIC     SET select_expr = (
-- MAGIC       SELECT string_agg(
-- MAGIC         CASE
-- MAGIC           WHEN columns_to_decrypt IS NULL OR array_contains(columns_to_decrypt, col)
-- MAGIC           THEN 'COALESCE(CAST(try_aes_decrypt(try_to_binary(' || col || ', ' || quote('BASE64') || '), unbase64(secret(' || decrypt_key || ')), ' || quote('GCM') || ', ' || quote('DEFAULT') || ') AS STRING), ' || col || ') AS ' || col
-- MAGIC           ELSE col
-- MAGIC         END,
-- MAGIC         ', '
-- MAGIC       )
-- MAGIC       FROM explode(all_cols) AS t(col)
-- MAGIC     );
-- MAGIC   END IF;
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

-- Load the titanic CSV from the volume into a temp view (no unencrypted data persisted)
CREATE OR REPLACE TEMPORARY VIEW titanic_raw AS
SELECT * FROM read_files(
  concat('/Volumes/', :catalog, '/', :schema, '/raw_files/titanic.csv'),
  format => 'csv',
  header => 'true'
);

-- Encrypt every column and write to a new table
CALL aes_encrypt_table(
  source_table => 'titanic_raw',
  secret_scope => :secret_scope,
  secret_key => :secret_key,
  target_table => :catalog || '.' || :schema || '.titanic_encrypted'
);

-- COMMAND ----------

SELECT * FROM titanic_encrypted

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 7: Decrypt all columns back and verify round-trip

-- COMMAND ----------

-- Using an unqualified table name — resolved via current_catalog() and current_schema()
CALL aes_decrypt_table(
  source_table => 'titanic_encrypted',
  secret_scope => :secret_scope,
  secret_key => :secret_key
);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 8: Encrypt only specific columns

-- COMMAND ----------

-- Only encrypt the sensitive columns, leaving customer_id in the clear
CALL aes_encrypt_table(
  source_table => 'titanic_raw',
  secret_scope => :secret_scope,
  secret_key => :secret_key,
  columns_to_encrypt => ARRAY('Name', 'Sex', 'Age'),
  target_table => :catalog || '.' || :schema || '.titanic_encrypted_pii_columns_only'
);

-- COMMAND ----------

SELECT * FROM titanic_encrypted_pii_columns_only

-- COMMAND ----------

-- Decrypt just the columns we think are encrypted
CALL aes_decrypt_table(
  source_table => :catalog || '.' || :schema || '.titanic_encrypted_pii_columns_only',
  secret_scope => :secret_scope,
  secret_key => :secret_key,
  columns_to_decrypt => NULL
);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 9: Encrypt by Databricks data-classification system tags
-- MAGIC
-- MAGIC Databricks can [automatically classify columns](https://docs.databricks.com/aws/en/data-governance/unity-catalog/data-classification-tags) by scanning table data and assigning system tags such as `class.name`, `class.email_address`, `class.age`, etc.
-- MAGIC
-- MAGIC Instead of listing column names explicitly, you can encrypt/decrypt every column that the classifier has tagged — just pass the relevant `class.*` tag names to the `tags` parameter.
-- MAGIC
-- MAGIC > **Note:** System tags are assigned asynchronously after data is written. If the tags haven't appeared yet, you can trigger classification manually via the Catalog Explorer UI or by calling `SELECT * FROM system.information_schema.column_tags WHERE table_name = 'titanic_tagged'` to check.

-- COMMAND ----------

-- Persist titanic_raw as a table so data classification can scan it
CREATE OR REPLACE TABLE IDENTIFIER(:catalog || '.' || :schema || '.titanic_tagged') AS
SELECT * FROM titanic_raw;

-- COMMAND ----------

-- Encrypt only the columns that the classifier tagged as class.name or class.age
CALL aes_encrypt_table(
  source_table => :catalog || '.' || :schema || '.titanic_tagged',
  secret_scope => :secret_scope,
  secret_key => :secret_key,
  tags => ARRAY('class.name', 'class.age'),
  target_table => :catalog || '.' || :schema || '.titanic_encrypted_by_tag'
);

-- COMMAND ----------

SELECT * FROM titanic_encrypted_by_tag

-- COMMAND ----------

-- Decrypt the tagged columns back
CALL aes_decrypt_table(
  source_table => :catalog || '.' || :schema || '.titanic_encrypted_by_tag',
  secret_scope => :secret_scope,
  secret_key => :secret_key,
  tags => ARRAY('class.name', 'class.age')
);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 10: Call from PySpark
-- MAGIC
-- MAGIC The procedures are equally callable from PySpark using `spark.sql()`.

-- COMMAND ----------

-- MAGIC %python
-- MAGIC # Encrypt specific columns and return as a DataFrame
-- MAGIC encrypted_df = spark.sql(f"""
-- MAGIC   CALL aes_encrypt_table(
-- MAGIC     source_table => 'titanic_raw',
-- MAGIC     secret_scope => '{secret_scope}',
-- MAGIC     secret_key => '{secret_key}',
-- MAGIC     columns_to_encrypt => ARRAY('Name', 'Sex', 'Age')
-- MAGIC   )
-- MAGIC """)
-- MAGIC display(encrypted_df)

-- COMMAND ----------

-- MAGIC %python
-- MAGIC # Encrypt all columns of a table and write to a new table
-- MAGIC spark.sql(f"""
-- MAGIC   CALL aes_encrypt_table(
-- MAGIC     source_table => 'titanic_raw',
-- MAGIC     secret_scope => '{secret_scope}',
-- MAGIC     secret_key => '{secret_key}',
-- MAGIC     target_table => '{catalog}.{schema}.titanic_encrypted_pyspark'
-- MAGIC   )
-- MAGIC """)
-- MAGIC display(spark.table(f"{catalog}.{schema}.titanic_encrypted_pyspark"))

-- COMMAND ----------

-- MAGIC %python
-- MAGIC # Decrypt all columns back and return as a DataFrame
-- MAGIC decrypted_df = spark.sql(f"""
-- MAGIC   CALL aes_decrypt_table(
-- MAGIC     source_table => '{catalog}.{schema}.titanic_encrypted_pyspark',
-- MAGIC     secret_scope => '{secret_scope}',
-- MAGIC     secret_key => '{secret_key}'
-- MAGIC   )
-- MAGIC """)
-- MAGIC display(decrypted_df)

-- Databricks notebook source
-- MAGIC %md
-- MAGIC # AES Encrypt / Decrypt Table
-- MAGIC This notebook creates two stored procedures — `aes_encrypt_table()` and `aes_decrypt_table()` — that apply AES encryption or decryption across an entire table (or a specified subset of columns).
-- MAGIC
-- MAGIC **Key features:**
-- MAGIC - Encrypts/decrypts all columns or a user-specified list of columns
-- MAGIC - Works on tables, views, and temp views (i.e. DataFrames registered via `createOrReplaceTempView`)
-- MAGIC - Optionally writes results to a target table, or returns a result set
-- MAGIC - Uses `secret()` to retrieve the AES key from Databricks Secrets
-- MAGIC - Pure SQL — no Python required (callable from both SQL and PySpark)

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 1: Setup — configure the catalog, schema and secret scope

-- COMMAND ----------

CREATE WIDGET TEXT catalog DEFAULT 'main';
CREATE WIDGET TEXT schema DEFAULT 'default';
CREATE WIDGET TEXT secret_scope DEFAULT '';
CREATE WIDGET TEXT secret_key DEFAULT '';

-- COMMAND ----------

USE CATALOG IDENTIFIER(:catalog);
USE SCHEMA IDENTIFIER(:schema);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 2: Generate some fake PII data to demonstrate with

-- COMMAND ----------

-- MAGIC %python
-- MAGIC # We use the shared helper to generate fake PII and register it as both a table and a temp view
-- MAGIC # so we can demonstrate the procedures on both
-- MAGIC %run ../../common/privacy_functions

-- COMMAND ----------

-- MAGIC %python
-- MAGIC catalog = dbutils.widgets.get("catalog")
-- MAGIC schema = dbutils.widgets.get("schema")
-- MAGIC
-- MAGIC df = generate_fake_pii_data(num_rows=100).select(
-- MAGIC     "customer_id", "name", "email", "date_of_birth", "ssn", "phone_number", "credit_card", "iban", "ipv4", "address"
-- MAGIC )
-- MAGIC
-- MAGIC # Write to a Unity Catalog table
-- MAGIC df.write.mode("overwrite").saveAsTable(f"{catalog}.{schema}.fake_pii_raw")
-- MAGIC
-- MAGIC # Also register as a temp view to demonstrate DataFrame usage
-- MAGIC df.createOrReplaceTempView("fake_pii_df")

-- COMMAND ----------

SELECT * FROM fake_pii_raw

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 3: Create the `aes_encrypt_table` stored procedure
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

CREATE OR REPLACE PROCEDURE aes_encrypt_table(
  source_table STRING,
  secret_scope STRING,
  secret_key STRING,
  columns_to_encrypt STRING DEFAULT '*',
  target_table STRING DEFAULT ''
)
LANGUAGE SQL
BEGIN
  -- Build comma-separated list of columns to encrypt (or all columns if '*')
  DECLARE encrypt_cols ARRAY<STRING>;
  DECLARE all_cols ARRAY<STRING>;
  DECLARE select_expr STRING DEFAULT '';
  DECLARE i INT DEFAULT 0;
  DECLARE col_name STRING;

  -- Get all column names from the source table
  SET all_cols = (
    SELECT collect_list(column_name)
    FROM system.information_schema.columns
    WHERE concat_ws('.', table_catalog, table_schema, table_name) = source_table
    ORDER BY ordinal_position
  );

  -- If the table wasn't found in information_schema (e.g. it's a temp view), use DESCRIBE
  IF (all_cols IS NULL OR size(all_cols) = 0) THEN
    SET all_cols = (
      SELECT collect_list(col_name) FROM (DESCRIBE TABLE IDENTIFIER(source_table))
    );
  END IF;

  -- Determine which columns to encrypt
  IF (columns_to_encrypt = '*') THEN
    SET encrypt_cols = all_cols;
  ELSE
    SET encrypt_cols = (SELECT collect_list(trim(value)) FROM (SELECT explode(split(columns_to_encrypt, ',')) AS value));
  END IF;

  -- Build the SELECT expression
  SET i = 0;
  WHILE i < size(all_cols) DO
    SET col_name = all_cols[i];
    IF (i > 0) THEN
      SET select_expr = select_expr || ', ';
    END IF;
    IF (array_contains(encrypt_cols, col_name)) THEN
      SET select_expr = select_expr || 'base64(aes_encrypt(CAST(' || col_name || ' AS STRING), secret(' || quote(secret_scope) || ', ' || quote(secret_key) || '), \'GCM\', \'DEFAULT\')) AS ' || col_name;
    ELSE
      SET select_expr = select_expr || col_name;
    END IF;
    SET i = i + 1;
  END WHILE;

  -- Execute the query
  IF (target_table != '') THEN
    EXECUTE IMMEDIATE ('CREATE OR REPLACE TABLE ' || target_table || ' AS SELECT ' || select_expr || ' FROM ' || source_table);
  ELSE
    EXECUTE IMMEDIATE ('SELECT ' || select_expr || ' FROM ' || source_table);
  END IF;
END;

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 4: Create the `aes_decrypt_table` stored procedure
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

CREATE OR REPLACE PROCEDURE aes_decrypt_table(
  source_table STRING,
  secret_scope STRING,
  secret_key STRING,
  columns_to_decrypt STRING DEFAULT '*',
  target_table STRING DEFAULT ''
)
LANGUAGE SQL
BEGIN
  DECLARE decrypt_cols ARRAY<STRING>;
  DECLARE all_cols ARRAY<STRING>;
  DECLARE select_expr STRING DEFAULT '';
  DECLARE i INT DEFAULT 0;
  DECLARE col_name STRING;

  -- Get all column names from the source table
  SET all_cols = (
    SELECT collect_list(column_name)
    FROM system.information_schema.columns
    WHERE concat_ws('.', table_catalog, table_schema, table_name) = source_table
    ORDER BY ordinal_position
  );

  -- Fallback for temp views
  IF (all_cols IS NULL OR size(all_cols) = 0) THEN
    SET all_cols = (
      SELECT collect_list(col_name) FROM (DESCRIBE TABLE IDENTIFIER(source_table))
    );
  END IF;

  -- Determine which columns to decrypt
  IF (columns_to_decrypt = '*') THEN
    SET decrypt_cols = all_cols;
  ELSE
    SET decrypt_cols = (SELECT collect_list(trim(value)) FROM (SELECT explode(split(columns_to_decrypt, ',')) AS value));
  END IF;

  -- Build the SELECT expression
  SET i = 0;
  WHILE i < size(all_cols) DO
    SET col_name = all_cols[i];
    IF (i > 0) THEN
      SET select_expr = select_expr || ', ';
    END IF;
    IF (array_contains(decrypt_cols, col_name)) THEN
      SET select_expr = select_expr || 'CAST(aes_decrypt(unbase64(' || col_name || '), secret(' || quote(secret_scope) || ', ' || quote(secret_key) || '), \'GCM\', \'DEFAULT\') AS STRING) AS ' || col_name;
    ELSE
      SET select_expr = select_expr || col_name;
    END IF;
    SET i = i + 1;
  END WHILE;

  -- Execute the query
  IF (target_table != '') THEN
    EXECUTE IMMEDIATE ('CREATE OR REPLACE TABLE ' || target_table || ' AS SELECT ' || select_expr || ' FROM ' || source_table);
  ELSE
    EXECUTE IMMEDIATE ('SELECT ' || select_expr || ' FROM ' || source_table);
  END IF;
END;

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 5: Encrypt all columns of a table

-- COMMAND ----------

-- Encrypt every column and write to a new table
CALL aes_encrypt_table(
  source_table => :catalog || '.' || :schema || '.fake_pii_raw',
  secret_scope => :secret_scope,
  secret_key => :secret_key,
  columns_to_encrypt => '*',
  target_table => :catalog || '.' || :schema || '.fake_pii_encrypted'
);

-- COMMAND ----------

SELECT * FROM fake_pii_encrypted

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 6: Decrypt all columns back and verify round-trip

-- COMMAND ----------

CALL aes_decrypt_table(
  source_table => :catalog || '.' || :schema || '.fake_pii_encrypted',
  secret_scope => :secret_scope,
  secret_key => :secret_key
);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 7: Encrypt only specific columns

-- COMMAND ----------

-- Only encrypt the sensitive columns, leaving customer_id in the clear
CALL aes_encrypt_table(
  source_table => :catalog || '.' || :schema || '.fake_pii_raw',
  secret_scope => :secret_scope,
  secret_key => :secret_key,
  columns_to_encrypt => 'name,email,ssn,phone_number,credit_card,iban,address',
  target_table => :catalog || '.' || :schema || '.fake_pii_partial_encrypted'
);

-- COMMAND ----------

SELECT * FROM fake_pii_partial_encrypted

-- COMMAND ----------

-- Decrypt just the columns we encrypted
CALL aes_decrypt_table(
  source_table => :catalog || '.' || :schema || '.fake_pii_partial_encrypted',
  secret_scope => :secret_scope,
  secret_key => :secret_key,
  columns_to_decrypt => 'name,email,ssn,phone_number,credit_card,iban,address'
);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 8: Use with a DataFrame (temp view)

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
-- MAGIC ## Step 9: Call from PySpark
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

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Cleanup

-- COMMAND ----------

-- DROP TABLE IF EXISTS fake_pii_raw;
-- DROP TABLE IF EXISTS fake_pii_encrypted;
-- DROP TABLE IF EXISTS fake_pii_partial_encrypted;
-- DROP PROCEDURE IF EXISTS aes_encrypt_table;
-- DROP PROCEDURE IF EXISTS aes_decrypt_table;

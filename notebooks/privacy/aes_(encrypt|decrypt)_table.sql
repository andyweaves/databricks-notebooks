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
-- MAGIC dbutils.widgets.text(name="secret_scope", defaultValue="", label="Secret Scope to use for DEK")
-- MAGIC dbutils.widgets.text(name="secret_key", defaultValue="", label="Secret Key to use for DEK")
-- MAGIC
-- MAGIC catalog = dbutils.widgets.get("catalog")
-- MAGIC schema = dbutils.widgets.get("schema")
-- MAGIC secret_scope = dbutils.widgets.get("secret_scope")
-- MAGIC secret_key = dbutils.widgets.get("secret_key")

-- COMMAND ----------

USE CATALOG IDENTIFIER(:catalog);
USE SCHEMA IDENTIFIER(:schema);

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
-- MAGIC ## Step 3: Generate some fake PII data to demonstrate with

-- COMMAND ----------

-- DBTITLE 1,Install faker and mimesis
-- MAGIC %python
-- MAGIC import subprocess, sys
-- MAGIC subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'faker', 'mimesis', '-q'])

-- COMMAND ----------

-- MAGIC %python
-- MAGIC # Inlined from ../../common/privacy_functions (because %run is not supported on serverless compute)
-- MAGIC
-- MAGIC import pandas as pd
-- MAGIC from typing import Iterator
-- MAGIC from pyspark.sql.functions import pandas_udf, col, spark_partition_id, asc, create_map, array, lit, udf
-- MAGIC from pyspark.sql.types import *
-- MAGIC import time
-- MAGIC from datetime import date
-- MAGIC import random
-- MAGIC from faker import Faker
-- MAGIC from mimesis import Generic
-- MAGIC from mimesis.locales import Locale
-- MAGIC
-- MAGIC schema = StructType([
-- MAGIC   StructField("customer_id", LongType(), False),
-- MAGIC   StructField("name", StringType(), False),
-- MAGIC   StructField("email", StringType(), False),
-- MAGIC   StructField("date_of_birth", DateType(), False),
-- MAGIC   StructField("age", LongType(), False),
-- MAGIC   StructField("address", StringType(), False),
-- MAGIC   StructField("postcode", StringType(), False),
-- MAGIC   StructField("ipv4", StringType(), False),
-- MAGIC   StructField("ipv4_with_port", StringType(), False),
-- MAGIC   StructField("ipv6", StringType(), False),
-- MAGIC   StructField("mac_address", StringType(), False),
-- MAGIC   StructField("phone_number", StringType(), False),
-- MAGIC   StructField("ssn", StringType(), False),
-- MAGIC   StructField("itin", StringType(), False),
-- MAGIC   StructField("iban", StringType(), False),
-- MAGIC   StructField("credit_card", LongType(), False),
-- MAGIC   StructField("credit_card_with_spaces", StringType(), False),
-- MAGIC   StructField("credit_card_full", StringType(), False),
-- MAGIC   StructField("expiry_date", StringType(), False),
-- MAGIC   StructField("security_code", StringType(), False),
-- MAGIC   StructField("freetext", StringType(), False),
-- MAGIC   StructField("passport", StringType(), False),
-- MAGIC   StructField("aba", StringType(), False),
-- MAGIC   StructField("bban", StringType(), False),
-- MAGIC   StructField("uri", StringType(), False),
-- MAGIC   StructField("url", StringType(), False),
-- MAGIC   StructField("language", StringType(), False),
-- MAGIC   StructField("nationality", StringType(), False),
-- MAGIC   StructField("country", StringType(), False),
-- MAGIC   StructField("date_time", StringType(), False),
-- MAGIC ])
-- MAGIC
-- MAGIC fake = Faker("en_US")
-- MAGIC generic = Generic(locale=Locale.EN, seed=1)
-- MAGIC
-- MAGIC def get_random_pii():
-- MAGIC   return random.choice([fake.ascii_free_email(), fake.ipv4(), fake.ipv6()])
-- MAGIC
-- MAGIC @pandas_udf("long")
-- MAGIC def get_customer_id(batch_iter: Iterator[pd.Series]) -> Iterator[pd.Series]:
-- MAGIC   for id in batch_iter:
-- MAGIC       yield int(time.time()) + id
-- MAGIC
-- MAGIC pii_struct_schema = StructType([
-- MAGIC     StructField("email_address", StringType(), False),
-- MAGIC     StructField("ipv4_private", StringType(), False),
-- MAGIC     StructField("ip_address_v6", StringType(), False),
-- MAGIC     StructField("ipv4_with_port", StringType(), False),
-- MAGIC     StructField("mac", StringType(), False),
-- MAGIC     StructField("imei", StringType(), False),
-- MAGIC     StructField("credit_card_number", StringType(), False),
-- MAGIC     StructField("credit_card_expiration_date", StringType(), False),
-- MAGIC     StructField("cvv", StringType(), False),
-- MAGIC     StructField("paypal", StringType(), False),
-- MAGIC     StructField("random_text_with_email", StringType(), False),
-- MAGIC     StructField("random_text_with_ipv4", StringType(), False)
-- MAGIC ])
-- MAGIC
-- MAGIC def pii_struct():
-- MAGIC   return (generic.person.email(), fake.ipv4_private(), fake.ipv6(), generic.internet.ip_v4_with_port(), generic.internet.mac_address(), generic.code.imei(), generic.payment.credit_card_number(), generic.payment.credit_card_expiration_date(), generic.payment.cvv(), generic.payment.paypal(), f"{fake.catch_phrase()} {generic.person.email()}", f"{fake.catch_phrase()} {fake.ipv4_public()}")
-- MAGIC
-- MAGIC pii_struct_udf = udf(pii_struct, pii_struct_schema)
-- MAGIC
-- MAGIC def generate_fake_data(pdf: pd.DataFrame) -> pd.DataFrame:
-- MAGIC   def generate_data(y):
-- MAGIC     dob = fake.date_between(start_date='-99y', end_date='-18y')
-- MAGIC     y["name"] = fake.name()
-- MAGIC     y["email"] = fake.ascii_free_email()
-- MAGIC     y["date_of_birth"] = dob
-- MAGIC     y["age"] = date.today().year - dob.year
-- MAGIC     y["address"] = fake.address()
-- MAGIC     y["ipv4"] = fake.ipv4()
-- MAGIC     y["ipv4_with_port"] = generic.internet.ip_v4_with_port()
-- MAGIC     y["ipv6"] = fake.ipv6()
-- MAGIC     y["mac_address"] = fake.mac_address()
-- MAGIC     y["postcode"] = fake.postcode()
-- MAGIC     y["phone_number"] = fake.phone_number()
-- MAGIC     y["ssn"] = fake.ssn()
-- MAGIC     y["itin"] = fake.itin()
-- MAGIC     y["iban"] = fake.iban()
-- MAGIC     y["credit_card"] = int(fake.credit_card_number())
-- MAGIC     y["credit_card_with_spaces"] = generic.payment.credit_card_number()
-- MAGIC     y["credit_card_full"] = fake.credit_card_full()
-- MAGIC     y["expiry_date"] = fake.credit_card_expire()
-- MAGIC     y["security_code"] = fake.credit_card_security_code()
-- MAGIC     y["freetext"] = f"{fake.sentence()} {get_random_pii()} {fake.sentence()} {get_random_pii()} {fake.sentence()}"
-- MAGIC     y["passport"] = fake.passport_number()
-- MAGIC     y["aba"] = fake.aba()
-- MAGIC     y["bban"] = fake.bban()
-- MAGIC     y["uri"] = fake.uri()
-- MAGIC     y["url"] = fake.url()
-- MAGIC     y["language"] = generic.person.language()
-- MAGIC     y["nationality"] = generic.person.nationality()
-- MAGIC     y["country"] = fake.country()
-- MAGIC     y["date_time"] = fake.date_time().strftime("%c")
-- MAGIC     return y
-- MAGIC   return pdf.apply(generate_data, axis=1).drop(["partition_id", "id"], axis=1)
-- MAGIC
-- MAGIC def generate_fake_pii_data(num_rows=1000):
-- MAGIC   initial_data = spark.range(1, num_rows+1).withColumn("customer_id", get_customer_id(col("id")))
-- MAGIC   return (
-- MAGIC     initial_data
-- MAGIC     .withColumn("partition_id", spark_partition_id())
-- MAGIC     .groupBy("partition_id")
-- MAGIC     .applyInPandas(generate_fake_data, schema)
-- MAGIC     .withColumn("pii_struct", pii_struct_udf())
-- MAGIC     .withColumn("pii_map", create_map(lit("email_address"), col("email"), lit("ip_address"), col("ipv4"), lit("home_address"), col("address")))
-- MAGIC     .withColumn("pii_array", array("email", "ipv4", "ipv6"))
-- MAGIC     .orderBy(asc("customer_id")))

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
      SET select_expr = select_expr || 'base64(aes_encrypt(CAST(' || col_name || ' AS STRING), unbase64(secret(' || quote(secret_scope) || ', ' || quote(secret_key) || ')), \'GCM\', \'DEFAULT\')) AS ' || col_name;
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
      SET select_expr = select_expr || 'CAST(aes_decrypt(unbase64(' || col_name || '), unbase64(secret(' || quote(secret_scope) || ', ' || quote(secret_key) || ')), \'GCM\', \'DEFAULT\') AS STRING) AS ' || col_name;
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
-- MAGIC ## Step 6: Encrypt all columns of a table

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
-- MAGIC ## Step 7: Decrypt all columns back and verify round-trip

-- COMMAND ----------

CALL aes_decrypt_table(
  source_table => :catalog || '.' || :schema || '.fake_pii_encrypted',
  secret_scope => :secret_scope,
  secret_key => :secret_key
);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Step 8: Encrypt only specific columns

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

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Cleanup

-- COMMAND ----------

-- DROP TABLE IF EXISTS fake_pii_raw;
-- DROP TABLE IF EXISTS fake_pii_encrypted;
-- DROP TABLE IF EXISTS fake_pii_partial_encrypted;
-- DROP PROCEDURE IF EXISTS aes_encrypt_table;
-- DROP PROCEDURE IF EXISTS aes_decrypt_table;

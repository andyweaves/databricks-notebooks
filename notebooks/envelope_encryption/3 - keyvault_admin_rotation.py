# Databricks notebook source
dbutils.widgets.text(name="secret_scope", defaultValue="", label="The secret scope to use for DEKs")
dbutils.widgets.text(name="kek_name", defaultValue="", label="The name to use for our KEK")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 1
# MAGIC Generate a new Key Encryption Key (KEK)

# COMMAND ----------

from base64 import b64encode
from os import urandom

new_kek = b64encode(urandom(24)).decode('utf-8')

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 2
# MAGIC Use the KEK to re-encrypt the Data Encryption Key (DEK)

# COMMAND ----------

secret_scope = dbutils.widgets.get("secret_scope")
kek_name = dbutils.widgets.get("kek_name")

new_encrypted_dek = sql(f"SELECT base64(aes_encrypt(sys.crypto.unwrap_key(secret('{secret_scope}', 'dek'), '{kek_name}'), '{new_kek}', 'GCM', 'DEFAULT'))").first()[0]

new_encrypted_iv = sql(f"SELECT base64(aes_encrypt(sys.crypto.unwrap_key(secret('{secret_scope}', 'iv'), '{kek_name}'), '{new_kek}', 'GCM', 'DEFAULT'))").first()[0]

new_encrypted_aad = sql(f"SELECT base64(aes_encrypt(sys.crypto.unwrap_key(secret('{secret_scope}', 'aad'), '{kek_name}'), '{new_kek}', 'GCM', 'DEFAULT'))").first()[0]

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 3
# MAGIC Replace the DEK secrets with the new encrypted values

# COMMAND ----------

from databricks.sdk import WorkspaceClient

w = WorkspaceClient()

w.secrets.put_secret(scope=secret_scope, key='dek', string_value=new_encrypted_dek)
w.secrets.put_secret(scope=secret_scope, key='iv', string_value=new_encrypted_iv)
w.secrets.put_secret(scope=secret_scope, key='aad', string_value=new_encrypted_aad)

display(sql(f"SELECT * FROM list_secrets() WHERE scope = '{secret_scope}'"))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 4
# MAGIC Update our `sys.crypto.key_vault` table with the new KEK and mark the old key as no longer enabled

# COMMAND ----------

current_version = sql(f"SELECT MAX(key_version) AS current_version FROM sys.crypto.key_vault WHERE key_name = '{kek_name}' AND key_enabled").first()[0]
current_version

# COMMAND ----------

sql(f"""INSERT INTO sys.crypto.key_vault
(created_date, created_time, last_modified_time, created_by, managed_by, key_name, key_version, key_enabled, key_type, key) 
VALUES (current_date(), current_timestamp(), current_timestamp(), session_user(), session_user(), '{kek_name}', {current_version+1}, True, 'KEK', '{new_kek}')""")

# COMMAND ----------

sql(f"""UPDATE sys.crypto.key_vault SET last_modified_time = current_timestamp(), key_enabled = FALSE
    WHERE key_name = '{kek_name}' AND key_version = {current_version}""")

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM sys.crypto.key_vault
# MAGIC ORDER BY id DESC

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 5
# MAGIC Query the data and confirm that the data is decryped as expected

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT 
# MAGIC *
# MAGIC FROM main.default.titanic_encrypted

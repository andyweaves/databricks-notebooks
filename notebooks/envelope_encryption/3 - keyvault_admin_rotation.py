# Databricks notebook source
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

new_encrypted_dek = sql(f"SELECT base64(aes_encrypt(main.default.unwrap_key(secret('andrewweaver', 'dek'), 'andrewweaver-kek', (SELECT MAX(key_version) FROM sys.keyvault.keys WHERE key_name = 'andrewweaver-kek' AND key_enabled)), '{new_kek}', 'GCM', 'DEFAULT'))").first()[0]

new_encrypted_iv = sql(f"SELECT base64(aes_encrypt(main.default.unwrap_key(secret('andrewweaver', 'iv'), 'andrewweaver-kek', (SELECT MAX(key_version) FROM sys.keyvault.keys WHERE key_name = 'andrewweaver-kek' AND key_enabled)), '{new_kek}', 'GCM', 'DEFAULT'))").first()[0]

new_encrypted_aad = sql(f"SELECT base64(aes_encrypt(main.default.unwrap_key(secret('andrewweaver', 'aad'), 'andrewweaver-kek', (SELECT MAX(key_version) FROM sys.keyvault.keys WHERE key_name = 'andrewweaver-kek' AND key_enabled)), '{new_kek}', 'GCM', 'DEFAULT'))").first()[0]

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 3
# MAGIC Replace the DEK secrets with the new encrypted values

# COMMAND ----------

w.secrets.put_secret(scope=current_user, key='dek', string_value=new_encrypted_dek)
w.secrets.put_secret(scope=current_user, key='iv', string_value=new_encrypted_iv)
w.secrets.put_secret(scope=current_user, key='aad', string_value=new_encrypted_aad)

display(sql(f"SELECT * FROM list_secrets() WHERE scope = '{current_user}'"))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 4
# MAGIC Update our `sys.crypto.key_vault` table with the new KEK

# COMMAND ----------

current_version = sql("SELECT MAX(key_version) FROM sys.crypto.key_vault WHERE key_name = 'andrewweaver-kek' AND key_enabled").first()[0]
current_version

# COMMAND ----------

sql(f"""INSERT INTO sys.keyvault.keys 
(created_date, created_time, last_modified_time, created_by, managed_by, key_name, key_version, key_enabled, key_type, key) 
VALUES (current_date(), current_timestamp(), current_timestamp(), session_user(), session_user(), '{current_user}-kek', {current_version+1}, True, 'KEK', '{new_kek}')""")

# COMMAND ----------

sql(f"""UPDATE sys.keyvault.keys SET last_modified_time = current_timestamp(), key_enabled = FALSE
    WHERE key_name = 'andrewweaver-kek' AND key_version = {current_version}""")

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM sys.keyvault.keys
# MAGIC ORDER BY id DESC

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT 
# MAGIC *
# MAGIC FROM main.default.titanic_encrypted

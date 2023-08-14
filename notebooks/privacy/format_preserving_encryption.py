# Databricks notebook source
# MAGIC %pip install -q -r ../../requirements.txt

# COMMAND ----------

# MAGIC %run ../../common/privacy_functions

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1: Generate some fake PII data using ```faker```

# COMMAND ----------

df = generate_fake_pii_data(num_rows=1000).drop("age", "postcode", "expiry_date", "security_code", "pii_struct", "pii_map", "pii_array", "address", "freetext")
display(df)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2: Setup the encryption key and tweak

# COMMAND ----------

import secrets  
  
# If needed generate a 256 bit key, store as a secret...
key = secrets.token_bytes(32).hex()

# If needed generate a 7 byte tweak, store as a secret...
tweak = secrets.token_bytes(7).hex()

# It's highly recommended that you generate the key and tweak and then store them as Databricks secrets...

# key = dbutils.secrets.get("fpe_scope", "fpe_key")
# tweak = dbutils.secrets.get("fpe_scope", "fpe_tweak")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 3: Define the character sets and the expected behavior when we encounter special characters

# COMMAND ----------

# Determine what to do with any special characters in the plaintext...
#   Options are "tokenize", or "reassemble" where:
# 
#     1. "TOKENIZE" -> Tokenize the whole string including special characters with an ASCII charset 
#     2. "REASSEMBLE" -> Try and preserve the format of the input string by removing the special characters, 
#     tokenizing the alphanum characters and then reassembling both afterwards
#
SPECIAL_CHAR_MODE = "REASSEMBLE" 

# Define the character sets...
NUMERIC_CHARSET = "0123456789"
ALPA_CHARSET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHA_CHARSET_LOWER = "abcdefghijklmnopqrstuvwxyz"
ALPHA_CHARSET_ALL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHANUMERIC_CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
ASCII_CHARSET = """0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c"""
SPECIAL_CHARSET = """!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ """

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 4: Declare some helper functions and our Pandas UDF

# COMMAND ----------

from ff3 import FF3Cipher

# Helper functions
def reassemble_string(string: str, positions: list, characters: str) -> str:

  for i in range(len(positions)):  
    pos = positions[i]   
    char = characters[i]  
    string = string[:pos] + char + string[pos:]
  return string

def encrypt_or_decrypt(text: str, charset: str, operation: str) -> str:

  output = None
  c = FF3Cipher.withCustomAlphabet(key, tweak, charset)

  if len(text) > 28:
    split_string = lambda string: (lambda s: s[:-1] + [s[-2] + s[-1]] if len(s[-1]) < 4 else s)([string[i:i+23] for i in range(0, len(string), 23)])  
    split = split_string(text)
    if operation == "ENCRYPT":
      output = "".join(list(map(lambda x: c.encrypt(x), split)))
    elif operation == "DECRYPT":
      output = "".join(list(map(lambda x: c.decrypt(x), split)))
    else:
      raise NotImplementedError("Invalid option - must be 'ENCRYPT' or 'DECRYPT'")
  else:
    if operation == "ENCRYPT":
      output = c.encrypt(text)
    elif operation == "DECRYPT":
      output = c.decrypt(text)
    else:
      raise NotImplementedError("Invalid option - must be 'ENCRYPT' or 'DECRYPT'")
  return output
  
def encrypt_or_decrypt_alpha(text: str, operation: str) -> str:

  output = None
  if text.isupper():
    output = encrypt_or_decrypt(text, ALPA_CHARSET_UPPER, operation) 
  elif text.islower():
    output = encrypt_or_decrypt(text, ALPHA_CHARSET_LOWER, operation) 
  else:  
    output = encrypt_or_decrypt(text, ALPHA_CHARSET_ALL, operation)
  return output 

# COMMAND ----------

from pyspark.sql.functions import udf
from pyspark.sql.types import StringType

# Encryption functions...
def fpe_encrypt_or_decrypt(text: str, operation: str) -> str:

  output = None
  if len(text) < 6 or len(text) > 50:
    raise ValueError(f"Input string length {len(text)} is not within minimum or maximum bounds: {text}")

  if text.isnumeric():
    output = encrypt_or_decrypt(text, NUMERIC_CHARSET, operation)
    
  elif text.isalpha():
    output = encrypt_or_decrypt_alpha(text, operation)

  elif text.isalnum():
    output = encrypt_or_decrypt(text, ALPHANUMERIC_CHARSET, operation) 
  
  elif text.isascii():

    import re
    encrypt_or_decrypt_by_type = lambda x : encrypt_or_decrypt(x, NUMERIC_CHARSET, operation) if x.isnumeric() else encrypt_or_decrypt_alpha(x, operation) if x.isalpha() else encrypt_or_decrypt(x, ALPHANUMERIC_CHARSET, operation) if x.isalnum() else None 

    if SPECIAL_CHAR_MODE == "TOKENIZE":
      output = encrypt_or_decrypt(text, ASCII_CHARSET, operation)  

    elif SPECIAL_CHAR_MODE == "REASSEMBLE":
      extract_special_chars = lambda string: ([char for char in re.findall(r"[^\w]", string)], [i for i, char in enumerate(string) if char in SPECIAL_CHARSET])  
      characters, positions = extract_special_chars(text)
      text = re.sub("([^a-zA-Z0-9])", "", text)
      output = encrypt_or_decrypt_by_type(text)
      output = reassemble_string(output, positions, characters)
    else:
      raise NotImplementedError("Invalid option - must be 'TOKENIZE' or 'REASSEMBLE'")
  return output

# COMMAND ----------

from pyspark.sql.functions import pandas_udf
import pandas as pd

# Pyspark Pandas UDFs...
def fpe_encrypt_series(s: pd.Series) -> pd.Series:

  return s.astype(str).apply(lambda x: fpe_encrypt_or_decrypt(x, "ENCRYPT"))

fpe_encrypt_pandas_udf = pandas_udf(fpe_encrypt_series, returnType=StringType())

def fpe_decrypt_series(s: pd.Series) -> pd.Series:

  return s.astype(str).apply(lambda x: fpe_encrypt_or_decrypt(x, "DECRYPT"))

fpe_decrypt_pandas_udf = pandas_udf(fpe_decrypt_series, returnType=StringType())

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 5: Encrypt the data with FPE

# COMMAND ----------

from pyspark.sql.functions import col, cast

# Encrypt our data...
encrypted = (df
  .select(
    fpe_encrypt_pandas_udf(col("name")).alias("encrypted_name"),
    fpe_encrypt_pandas_udf(col("email")).alias("encrypted_email"),
    fpe_encrypt_pandas_udf(col("date_of_birth").cast("string")).alias("encrypted_date_of_birth"),
    fpe_encrypt_pandas_udf(col("ssn")).alias("encrypted_ssn"),
    fpe_encrypt_pandas_udf(col("ipv4")).alias("encrypted_ipv4"),
    fpe_encrypt_pandas_udf(col("ipv6")).alias("encrypted_ipv6"),
    fpe_encrypt_pandas_udf(col("mac_address")).alias("encrypted_mac_address"),
    fpe_encrypt_pandas_udf(col("phone_number")).alias("encrypted_phone_number"),
    fpe_encrypt_pandas_udf(col("iban")).alias("encrypted_iban"),
    fpe_encrypt_pandas_udf(col("credit_card").cast("string")).alias("encrypted_credit_card"),
  ))
display(encrypted)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 6: Decrypt the data with FPE

# COMMAND ----------

# Decrypt our data...
decrypted = (encrypted
  .select(
    fpe_decrypt_pandas_udf(col("encrypted_name")).alias("decrypted_name"),
    fpe_decrypt_pandas_udf(col("encrypted_email")).alias("decrypted_email"),
    fpe_decrypt_pandas_udf(col("encrypted_date_of_birth").cast("string")).alias("decrypted_date_of_birth"),
    fpe_decrypt_pandas_udf(col("encrypted_ssn")).alias("decrypted_ssn"),
    fpe_decrypt_pandas_udf(col("encrypted_ipv4")).alias("decrypted_ipv4"),
    fpe_decrypt_pandas_udf(col("encrypted_ipv6")).alias("decrypted_ipv6"),
    fpe_decrypt_pandas_udf(col("encrypted_mac_address")).alias("decrypted_mac_address"),
    fpe_decrypt_pandas_udf(col("encrypted_phone_number")).alias("decrypted_phone_number"),
    fpe_decrypt_pandas_udf(col("encrypted_iban")).alias("decrypted_iban"),
    fpe_decrypt_pandas_udf(col("encrypted_credit_card").cast("string")).alias("decrypted_credit_card"),
  ))
display(decrypted)

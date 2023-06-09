# Databricks notebook source
# MAGIC %run ../../common/install_libs

# COMMAND ----------

# MAGIC %run ../../common/functions

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1: Generate some fake PII data using ```faker```

# COMMAND ----------

df = generate_fake_pii_data(num_rows=1000).select("customer_id", "name", "email", "ssn", "iban", "credit_card", "phone_number", "date_of_birth", "ipv4", "ipv6", "freetext")
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

# I recommend that you generate the key and tweak and then store them as Databricks secrets...

# key = dbutils.secrets.get("scope", "fpe_key")
# tweak = dbutils.secrets.get("scope", "fpe_tweak")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 3: Define the character sets and the expected behavior when we encounter special characters

# COMMAND ----------

# Determine what to do with any special characters in the plaintext...
#   Options are "tokenize", "strip", or "reassemble" where:
# 
#     1. "tokenize" -> Tokenize the whole string including special characters with an ASCII charset 
#     2. "reassemble" -> Try and preserve the format of the input string by removing the special characters, tokenizing the alphanum characters and then reassembling both afterwards
#
special_char_mode="reassemble" 

# Define character sets...
numeric_charset = "0123456789"
alpha_charset_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
alpha_charset_lower = "abcdefghijklmnopqrstuvwxyz"
alpa_charset_all = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
alpanumeric_charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
ascii_charset = """0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c"""
special_charset = """!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ """

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

def encrypt(plaintext: str, charset: str) -> str:

  c = FF3Cipher.withCustomAlphabet(key, tweak, charset)

  if len(plaintext) > 28:
    split_string = lambda string: (lambda s: s[:-1] + [s[-2] + s[-1]] if len(s[-1]) < 4 else s)([string[i:i+23] for i in range(0, len(string), 23)])  
    split = split_string(plaintext)
    ciphertext = "".join(list(map(lambda x: c.encrypt(x), split)))
    return ciphertext
  else: 
    return c.encrypt(plaintext)

def decrypt(ciphertext: str, charset: str) -> str:

  c = FF3Cipher.withCustomAlphabet(key, tweak, charset)

  if len(ciphertext) > 28:
    split_string = lambda string: (lambda s: s[:-1] + [s[-2] + s[-1]] if len(s[-1]) < 4 else s)([string[i:i+23] for i in range(0, len(string), 23)])  
    split = split_string(ciphertext)
    plaintext = "".join(list(map(lambda x: c.decrypt(x), split)))
    return plaintext
  else: 
    return c.decrypt(ciphertext)

def encrypt_alpha(plaintext: str) -> str:
  if plaintext.isupper():
    ciphertext = encrypt(plaintext, alpha_charset_upper) 
  elif plaintext.islower():
    ciphertext = encrypt(plaintext, alpha_charset_lower) 
  else:  
    ciphertext = encrypt(plaintext, alpa_charset_all) 
  return ciphertext 

def decrypt_alpha(ciphertext: str) -> str:
  if ciphertext.isupper():
    plaintext = decrypt(ciphertext, alpha_charset_upper) 
  elif ciphertext.islower():
    plaintext = decrypt(ciphertext, alpha_charset_lower) 
  else:  
    plaintext = decrypt(ciphertext, alpa_charset_all) 
  return plaintext 

# COMMAND ----------

from pyspark.sql.functions import udf
from pyspark.sql.types import StringType

# Functions...
def fpe_encrypt(plaintext: str) -> str:

  if len(plaintext) < 6:
    raise ValueError(f"Plaintext length {len(plaintext)} is not within minimum bounds: {plaintext}")

  if plaintext.isnumeric():
    ciphertext = encrypt(plaintext, numeric_charset)
    
  elif plaintext.isalpha():
    ciphertext = encrypt_alpha(plaintext)

  elif plaintext.isalnum():
    ciphertext = encrypt(plaintext, alpanumeric_charset) 
  
  elif plaintext.isascii():

    import re
    encrypt_by_type = lambda x : encrypt(x, numeric_charset) if x.isnumeric() else encrypt_alpha(x) if x.isalpha() else encrypt(x, alpanumeric_charset) if x.isalnum() else None 

    if special_char_mode == "tokenize":
      ciphertext = encrypt(plaintext, ascii_charset)  

    elif special_char_mode == "reassemble":
      extract_special_chars = lambda string: ([char for char in re.findall(r"[^\w]", string)], [i for i, char in enumerate(string) if char in special_charset])  
      characters, positions = extract_special_chars(plaintext)
      plaintext = re.sub("([^a-zA-Z0-9])", "", plaintext)
      ciphertext = encrypt_by_type(plaintext)
      ciphertext = reassemble_string(ciphertext, positions, characters)

  return ciphertext

# COMMAND ----------

def fpe_decrypt(ciphertext: str) -> str:

  if len(ciphertext) < 6:
    raise ValueError(f"Plaintext length {len(ciphertext)} is not within minimum bounds: {ciphertext}")

  if ciphertext.isnumeric():
    plaintext = decrypt(ciphertext, numeric_charset)
    
  elif ciphertext.isalpha():
    plaintext = decrypt_alpha(ciphertext)

  elif ciphertext.isalnum():
    plaintext = decrypt(ciphertext, alpanumeric_charset) 
  
  elif ciphertext.isascii():

    import re
    decrypt_by_type = lambda x : decrypt(x, numeric_charset) if x.isnumeric() else decrypt_alpha(x) if x.isalpha() else decrypt(x, alpanumeric_charset) if x.isalnum() else None 

    if special_char_mode == "tokenize":
      plaintext = decrypt(ciphertext, ascii_charset)  

    elif special_char_mode == "reassemble":
      extract_special_chars = lambda string: ([char for char in re.findall(r"[^\w]", string)], [i for i, char in enumerate(string) if char in special_charset])  
      characters, positions = extract_special_chars(ciphertext)
      ciphertext = re.sub("([^a-zA-Z0-9])", "", ciphertext)
      plaintext = decrypt_by_type(ciphertext)
      plaintext = reassemble_string(plaintext, positions, characters)

  return plaintext

# COMMAND ----------

from pyspark.sql.functions import pandas_udf

# Pandas UDFs...
def fpe_encrypt_series(s: pd.Series) -> pd.Series:

  return s.astype(str).apply(lambda x: fpe_encrypt(x))

fpe_encrypt_pandas_udf = pandas_udf(fpe_encrypt_series, returnType=StringType())

def fpe_decrypt_series(s: pd.Series) -> pd.Series:

  return s.astype(str).apply(lambda x: fpe_decrypt(x))

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
    fpe_encrypt_pandas_udf(col("date_of_birth").cast("string")).alias("encrypted_date_of_birth"),
    fpe_encrypt_pandas_udf(col("ssn")).alias("encrypted_ssn"),
    fpe_encrypt_pandas_udf(col("ipv4")).alias("encrypted_ipv4"),
    fpe_encrypt_pandas_udf(col("ipv6")).alias("encrypted_ipv6"),
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
    fpe_decrypt_pandas_udf(col("encrypted_date_of_birth").cast("string")).alias("decrypted_date_of_birth"),
    fpe_decrypt_pandas_udf(col("encrypted_ssn")).alias("decrypted_ssn"),
    fpe_decrypt_pandas_udf(col("encrypted_ipv4")).alias("decrypted_ipv4"),
    fpe_decrypt_pandas_udf(col("encrypted_ipv6")).alias("decrypted_ipv6"),
    fpe_decrypt_pandas_udf(col("encrypted_credit_card").cast("string")).alias("decrypted_credit_card"),
  ))
display(decrypted)

# Databricks notebook source
# MAGIC %run ../../common/generate_fake_pii

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2: Generate some fake PII data using ```faker```

# COMMAND ----------

df = generate_fake_pii_data(num_rows=100000).select("customer_id", "name", "email", "ssn", "iban", "credit_card", "phone_number", "date_of_birth", "ipv4", "ipv6")
display(df)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2: Setup FPE key and tweak

# COMMAND ----------

import secrets  
  
# If needed generate a 256 bit key, store as a secret...
key = secrets.token_bytes(32).hex()

# If needed generate a 256 bit key, store as a secret...
tweak = secrets.token_bytes(7).hex()

# Retrieve the key & tweak...
key = dbutils.secrets.get("aweaver", "fpe_key")
tweak = dbutils.secrets.get("aweaver", "fpe_tweak")

# Determine what to do with any special characters in the plaintext...
#   Options are "tokenize", "strip", or "reassemble" where:
# 
#     1. "tokenize" -> Tokenize the whole string including special characters with an ASCII charset 
#     2. "strip" -> Strip the special characters and tokenize what's left
#     3. "reassemble" -> Try and preserve the format of the input string by removing the special characters, tokenizing the alphanum characters and then reassembling both afterwards
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

from ff3 import FF3Cipher

# Helper functions

def reassemble_string(string: str, positions: list, characters: str) -> str:
  for i in range(len(positions)):  
    pos = positions[i]   
    char = characters[i]  
    string = string[:pos] + char + string[pos:]
  return string
  
def encrypt_alpha(plaintext: str) -> str:
  if plaintext.isupper():
    ciphertext = encrypt(plaintext, alpha_charset_upper) 
  elif plaintext.islower():
    ciphertext = encrypt(plaintext, alpha_charset_lower) 
  else:  
    ciphertext = encrypt(plaintext, alpa_charset_all) 
  return ciphertext 

def encrypt(plaintext: str, charset: str) -> str:

  c = FF3Cipher.withCustomAlphabet(key, tweak, charset)

  if len(plaintext) > 28:
    split_string = lambda string: (lambda s: s[:-1] + [s[-2] + s[-1]] if len(s[-1]) < 4 else s)([string[i:i+23] for i in range(0, len(string), 23)])  
    split = split_string(plaintext)
    ciphertext = "".join(list(map(lambda x: c.encrypt(x), split)))
    return ciphertext
  else: 
    return c.encrypt(plaintext)

# COMMAND ----------

from pyspark.sql.functions import udf
from pyspark.sql.types import StringType

# Python UDF
def fpe_encrypt(plaintext: str) -> str:

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
    
    elif special_char_mode == "strip":
      plaintext = re.sub("([^a-zA-Z0-9])", "", plaintext)
      ciphertext = encrypt_by_type(plaintext)

    elif special_char_mode == "reassemble":
      extract_special_chars = lambda string: ([char for char in re.findall(r"[^\w]", string)], [i for i, char in enumerate(string) if char in special_charset])  
      characters, positions = extract_special_chars(plaintext)
      plaintext = re.sub("([^a-zA-Z0-9])", "", plaintext)
      ciphertext = encrypt_by_type(plaintext)
      ciphertext = reassemble_string(ciphertext, positions, characters)

  return ciphertext

fpe_encrypt_udf = udf(lambda x: fpe_encrypt(str(x)), StringType())

# COMMAND ----------

from pyspark.sql.functions import col, cast

# Test the Python UDF
tokenized = (df
  .select(
    "customer_id",
    "name",
    fpe_encrypt_udf(col("name")).alias("tokenized_name"),
    "date_of_birth",
    fpe_encrypt_udf(col("date_of_birth").cast("string")).alias("tokenized_date_of_birth"),
    "ssn",
    fpe_encrypt_udf(col("ssn")).alias("tokenized_ssn"),
    "iban",
    fpe_encrypt_udf(col("iban")).alias("tokenized_iban"),
    "credit_card",
    fpe_encrypt_udf(col("credit_card").cast("string")).alias("tokenized_credit_card"),
    "phone_number",
    fpe_encrypt_udf(col("phone_number")).alias("tokenized_phone_number"),
    "ipv4",
    fpe_encrypt_udf(col("ipv4")).alias("tokenized_ipv4"),
    "ipv6",
    fpe_encrypt_udf(col("ipv6")).alias("tokenized_ipv6")
  ))
display(tokenized)

# COMMAND ----------

from pyspark.sql.functions import pandas_udf

# Pandas UDF
def fpe_encrypt_series(s: pd.Series) -> pd.Series:

  return s.astype(str).apply(lambda x: fpe_encrypt(x))

fpe_encrypt_pandas_udf = pandas_udf(fpe_encrypt_series, returnType=StringType())

# COMMAND ----------

# Test the Pandas UDF

tokenized = (df
  .select(
    "customer_id",
    "name",
    fpe_encrypt_pandas_udf(col("name")).alias("tokenized_name"),
    "date_of_birth",
    fpe_encrypt_pandas_udf(col("date_of_birth").cast("string")).alias("tokenized_date_of_birth"),
    "ssn",
    fpe_encrypt_pandas_udf(col("ssn")).alias("tokenized_ssn"),
    "iban",
    fpe_encrypt_pandas_udf(col("iban")).alias("tokenized_iban"),
    "credit_card",
    fpe_encrypt_pandas_udf(col("credit_card").cast("string")).alias("tokenized_credit_card"),
    "phone_number",
    fpe_encrypt_pandas_udf(col("phone_number")).alias("tokenized_phone_number"),
    "ipv4",
    fpe_encrypt_pandas_udf(col("ipv4")).alias("tokenized_ipv4"),
    "ipv6",
    fpe_encrypt_pandas_udf(col("ipv6")).alias("tokenized_ipv6")
  ))
display(tokenized)

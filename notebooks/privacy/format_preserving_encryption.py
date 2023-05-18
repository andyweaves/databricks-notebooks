# Databricks notebook source
# MAGIC %run ../../common/generate_fake_pii

# COMMAND ----------

# MAGIC %sql
# MAGIC USE CATALOG diz

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE SCHEMA IF NOT EXISTS raw;
# MAGIC CREATE SCHEMA IF NOT EXISTS processed

# COMMAND ----------

df = generate_fake_pii_data(num_rows=1000).select("customer_id", "name", "email", "ssn", "iban", "credit_card", "phone_number", "date_of_birth", "ipv4", "ipv6")
display(df)

# COMMAND ----------

df.write.mode("overwrite").saveAsTable("diz.raw.fake_pii_data")

# COMMAND ----------

import secrets  
  
# Generate a 256 bit key
key = secrets.token_bytes(32).hex()

# Generate a 7 byte tweak
tweak = secrets.token_bytes(7).hex()

key = dbutils.secrets.get("aweaver", "fpe_key")
tweak = dbutils.secrets.get("aweaver", "fpe_tweak")

# COMMAND ----------

def fpe_encrypt(key, tweak, special_char_mode, plaintext):

  ciphertext = None

  numeric_charset = "0123456789"
  alpha_charset_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  alpha_charset_lower = "abcdefghijklmnopqrstuvwxyz"
  alpa_charset_all = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
  alpanumeric_charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
  ascii_charset = """0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c"""
  special_charset = """!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ """

  if not isinstance(plaintext, str):
    raise TypeError(f"Only strings can be FPE encrypted, but received {type(plaintext)}. Please cast to string.")

  from ff3 import FF3Cipher

  def encrypt(plaintext, charset):

    c = FF3Cipher(key, tweak, radix=10).withCustomAlphabet(key, tweak, charset)

    if len(plaintext) > 28:
      split_string = lambda string: (lambda s: s[:-1] + [s[-2] + s[-1]] if len(s[-1]) < 4 else s)([string[i:i+23] for i in range(0, len(string), 23)])  
      split = split_string(plaintext)
      ciphertext = "".join(list(map(lambda x: c.encrypt(x), split)))
      return ciphertext
    else: 
      return c.encrypt(plaintext)

  def reassemble_string(string, positions, characters):
    for i in range(len(positions)):  
      pos = positions[i]   
      char = characters[i]  
      string = string[:pos] + char + string[pos:]
    return string
  
  def encrypt_alpha(plaintext):
    if plaintext.isupper():
      ciphertext = encrypt(plaintext, alpa_charset_all) 
    elif plaintext.islower():
      ciphertext = encrypt(plaintext, alpa_charset_all) 
    else:  
      ciphertext = encrypt(plaintext, alpa_charset_all) 
    return ciphertext 

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

# COMMAND ----------

from pyspark.sql.functions import udf
from pyspark.sql.types import StringType

fpe_encrypt_udf = udf(lambda x: fpe_encrypt(key=key, tweak=tweak, special_char_mode="reassemble", plaintext=x), StringType())

# COMMAND ----------

from pyspark.sql.functions import col, cast
from pyspark.sql.types import StringType

tokenized = (spark.table("diz.raw.fake_pii_data")
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

import pandas as pd
from pyspark.sql.functions import col, pandas_udf
from pyspark.sql.types import LongType

# Declare the function and create the UDF
def multiply_func(a: pd.Series, b: pd.Series) -> pd.Series:
    return a * b

multiply = pandas_udf(multiply_func, returnType=LongType())

# The function for a pandas_udf should be able to execute with local pandas data
x = pd.Series([1, 2, 3])
print(multiply_func(x, x))
# 0    1
# 1    4
# 2    9
# dtype: int64

# Create a Spark DataFrame, 'spark' is an existing SparkSession
df = spark.createDataFrame(pd.DataFrame(x, columns=["x"]))

# Execute function as a Spark vectorized UDF
df.select(multiply(col("x"), col("x"))).show()

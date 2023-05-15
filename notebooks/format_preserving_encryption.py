# Databricks notebook source
# MAGIC %run ../common/generate_fake_pii

# COMMAND ----------

# MAGIC %sql
# MAGIC USE CATALOG diz

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE SCHEMA IF NOT EXISTS raw;
# MAGIC CREATE SCHEMA IF NOT EXISTS processed

# COMMAND ----------

df = generate_fake_pii_data(num_rows=1000).select("customer_id", "email", "phone_number", "postcode", "date_of_birth", "ipv4")
display(df)

# COMMAND ----------

df.write.mode("overwrite").saveAsTable("raw.fake_pii_data")

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

  numeric_alphabet = "0123456789"
  alpha_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
  alpanumeric_alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
  ascii_alphabet = """0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c"""
  special_char_list = """!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~"""

  if not isinstance(plaintext, str):
    raise TypeError(f"Only strings can be FPE encrypted, but received {type(plaintext)}. Please cast to string.")

  from ff3 import FF3Cipher

  def encrypt(plainext, alphabet):

    c = FF3Cipher.withCustomAlphabet(key, tweak, alphabet)

    if len(plaintext) > 28:
      split_string = lambda string: [string[i:i+23] for i in range(0, len(string), 23)]
      split = split_string(plaintext) 
      split[-2:] = [split[-2] + split[-1]] if len(split[-1]) < 4 else split
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

  if plaintext.isnumeric():
    ciphertext = encrypt(plaintext, numeric_alphabet)
    
  elif plaintext.isalpha():
    ciphertext = encrypt(plaintext, alpha_alphabet) 

  elif plaintext.isalnum():
    ciphertext = encrypt(plaintext, alpanumeric_alphabet) 
  
  elif plaintext.isascii():

    encrypt_by_type = lambda x : encrypt(x, numeric_alphabet) if x.isnumeric() else encrypt(x, alpha_alphabet) if x.isalpha() else encrypt(x, alpanumeric_alphabet) if x.isalnum() else None 

    import re

    if special_char_mode == "tokenize":
      ciphertext = encrypt(plaintext, ascii_alphabet)  
    
    elif special_char_mode == "strip":
      plaintext = re.sub("([^a-zA-Z0-9])", "", plaintext)
      ciphertext = encrypt_by_type(plaintext)

    elif special_char_mode == "reassemble":
      extract_special_chars = lambda string: ([char for char in re.findall(r"[^\w\s]", string)], [i for i, char in enumerate(string) if char in special_char_list])  
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

from pyspark.sql.functions import col

tokenized = (spark.table("raw.fake_pii_data")
  .select(
    "customer_id",
    "email",
    fpe_encrypt_udf(col("email")).alias("tokenized_email"),
    "ipv4",
    fpe_encrypt_udf(col("ipv4")).alias("tokenized_ipv4"),
    "postcode",
    fpe_encrypt_udf(col("postcode")).alias("tokenized_postcode"),
    "phone_number",
    fpe_encrypt_udf(col("phone_number")).alias("tokenized_phone_number")
  ))
display(tokenized)

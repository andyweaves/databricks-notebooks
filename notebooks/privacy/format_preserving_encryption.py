# Databricks notebook source
# MAGIC %pip install -q ff3-cryptography faker mimesis

# COMMAND ----------

# MAGIC %run ../../common/privacy_functions

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1: Generate some fake PII data using ```faker```

# COMMAND ----------

df = generate_fake_pii_data(num_rows=1000).drop("age", "postcode", "expiry_date", "security_code", "pii_struct", "pii_map", "pii_array", "freetext")
display(df)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2: Setup the encryption key and tweak

# COMMAND ----------

import secrets

# WARNING: The key and tweak below are generated at runtime for demonstration purposes only.
# In production, you MUST replace these with values stored in Databricks secrets (see commented lines below).
# If you regenerate key/tweak values, you will permanently lose the ability to decrypt any data
# that was encrypted with the previous key/tweak. Always persist and back up your keys.
key = secrets.token_bytes(32).hex()
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
ALPHA_CHARSET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHA_CHARSET_LOWER = "abcdefghijklmnopqrstuvwxyz"
ALPHA_CHARSET_ALL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHANUMERIC_CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
ASCII_CHARSET = """0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c"""
SPECIAL_CHARSET = """!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ """

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 4: Declare some helper functions and our Pandas UDF

# COMMAND ----------

from ff3_cryptography.algo import FF3Cipher
import re

# Supported charset names for explicit charset selection. By specifying the charset per-column,
# you avoid the auto-detection problem where encrypt picks one charset but decrypt picks another
# because the ciphertext has different character composition than the plaintext.
# See: https://github.com/stikkireddy/python-fpe-cryptography/issues/4
CHARSET_MAP = {
  "NUMERIC": NUMERIC_CHARSET,
  "ALPHA_UPPER": ALPHA_CHARSET_UPPER,
  "ALPHA_LOWER": ALPHA_CHARSET_LOWER,
  "ALPHA": ALPHA_CHARSET_ALL,
  "ALPHANUMERIC": ALPHANUMERIC_CHARSET,
  "ASCII": ASCII_CHARSET,
}

def reassemble_string(input_str: str, positions: list, characters: str) -> str:
  """Reassemble special characters back into the encrypted/decrypted string at their original positions.

  Fixed version: tracks actual string length as insertions shift positions, and validates bounds.
  """
  assert len(positions) == len(characters), "Length of positions and characters must be equal"
  input_str_length = len(input_str)
  for i in range(len(positions)):
    pos = positions[i]
    char = characters[i]
    if pos < input_str_length:
      input_str = input_str[:pos] + char + input_str[pos:]
      input_str_length = len(input_str)
    elif pos == input_str_length:
      input_str = input_str + char
      input_str_length = len(input_str)
    else:
      raise ValueError(f"Position {pos} is out of bounds for string of length {input_str_length}")
  return input_str

def encrypt_or_decrypt(text: str, charset: str, operation: str) -> str:

  c = FF3Cipher.withCustomAlphabet(key, tweak, charset)
  split_string = lambda string: (lambda s: s[:-1] + [s[-2] + s[-1]] if len(s[-1]) < 4 else s)([string[i:i+23] for i in range(0, len(string), 23)])

  if len(text) > 28:
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

def _auto_detect_charset(text: str) -> str:
  """Auto-detect charset from text content. Safe for NUMERIC and ALPHANUMERIC, but note that
  alpha-only inputs will use ALPHANUMERIC to avoid round-trip failures. Use explicit charset
  parameter if you need alpha-only format preservation.
  """
  if text.isnumeric():
    return NUMERIC_CHARSET
  elif text.isalnum():
    return ALPHANUMERIC_CHARSET
  else:
    raise ValueError(f"text: {text} should be either numeric or alphanumeric")

# COMMAND ----------

from pyspark.sql.functions import udf
from pyspark.sql.types import StringType

def fpe_encrypt_or_decrypt(text: str, operation: str, charset: str = None) -> str:
  """Encrypt or decrypt text using FF3 format-preserving encryption.

  Args:
    text: The plaintext (for ENCRYPT) or ciphertext (for DECRYPT).
    operation: "ENCRYPT" or "DECRYPT".
    charset: Optional. One of "NUMERIC", "ALPHA_UPPER", "ALPHA_LOWER", "ALPHA", "ALPHANUMERIC", "ASCII".
             When specified, this charset is used directly for the non-special characters, ensuring
             encrypt and decrypt always agree. When None, charset is auto-detected from the text content
             (safe for NUMERIC and ALPHANUMERIC; alpha-only inputs fall back to ALPHANUMERIC).
  """

  if len(text) < 6:
    raise ValueError(f"Input string length {len(text)} is not within minimum bounds: 6")

  if len(text) >= 47:
    raise ValueError(f"Input length {len(text)} is not within max bounds of: 47")

  # If an explicit charset is provided, use it directly (handles special chars via REASSEMBLE)
  if charset is not None:
    if charset not in CHARSET_MAP:
      raise ValueError(f"Unknown charset '{charset}'. Must be one of: {list(CHARSET_MAP.keys())}")
    resolved_charset = CHARSET_MAP[charset]

    if not text.isascii():
      raise ValueError(f"Input text contains non-ASCII characters")

    # For pure charset inputs (no special chars), encrypt/decrypt directly
    if all(c in resolved_charset for c in text):
      return encrypt_or_decrypt(text, resolved_charset, operation)

    # Otherwise, strip special chars, encrypt/decrypt the core, and reassemble
    extract_special_chars = lambda string: ([char for char in re.findall(r"[^a-zA-Z0-9]", string)], [i for i, char in enumerate(string) if char in SPECIAL_CHARSET])
    characters, positions = extract_special_chars(text)
    removed = re.sub("([^a-zA-Z0-9])", "", text)
    encrypted_decrypted = encrypt_or_decrypt(removed, resolved_charset, operation)
    return reassemble_string(encrypted_decrypted, positions, characters)

  # Auto-detect mode (original behavior, safe for numeric/alphanumeric)
  if text.isnumeric():
    return encrypt_or_decrypt(text, NUMERIC_CHARSET, operation)

  elif text.isalnum():
    return encrypt_or_decrypt(text, ALPHANUMERIC_CHARSET, operation)

  elif text.isascii():

    if SPECIAL_CHAR_MODE == "TOKENIZE":
      return encrypt_or_decrypt(text, ASCII_CHARSET, operation)
    elif SPECIAL_CHAR_MODE == "REASSEMBLE":
      # Use [^a-zA-Z0-9] instead of [^\w] to correctly treat underscores as special characters
      extract_special_chars = lambda string: ([char for char in re.findall(r"[^a-zA-Z0-9]", string)], [i for i, char in enumerate(string) if char in SPECIAL_CHARSET])
      characters, positions = extract_special_chars(text)
      removed = re.sub("([^a-zA-Z0-9])", "", text)
      encrypted_decrypted = _auto_detect_charset(removed)
      encrypted_decrypted = encrypt_or_decrypt(removed, encrypted_decrypted, operation)
      reassembled = reassemble_string(encrypted_decrypted, positions, characters)
      return reassembled
    else:
      raise NotImplementedError("Invalid option - must be 'TOKENIZE' or 'REASSEMBLE'")

# COMMAND ----------

from pyspark.sql.functions import pandas_udf
import pandas as pd

# Auto-detect Pandas UDFs (backward compatible - safe for numeric/alphanumeric columns)...
def fpe_encrypt_series(s: pd.Series) -> pd.Series:
  return s.astype(str).apply(lambda x: fpe_encrypt_or_decrypt(x, "ENCRYPT"))

fpe_encrypt_pandas_udf = pandas_udf(fpe_encrypt_series, returnType=StringType())

def fpe_decrypt_series(s: pd.Series) -> pd.Series:
  return s.astype(str).apply(lambda x: fpe_encrypt_or_decrypt(x, "DECRYPT"))

fpe_decrypt_pandas_udf = pandas_udf(fpe_decrypt_series, returnType=StringType())

# Factory for charset-specific Pandas UDFs. Use these when you know the column's charset upfront.
# This fixes https://github.com/stikkireddy/python-fpe-cryptography/issues/4 - alpha-only columns
# (e.g. names) will now correctly round-trip because both encrypt and decrypt use the same charset.
def make_fpe_pandas_udf(charset: str, operation: str):
  def _series_fn(s: pd.Series) -> pd.Series:
    return s.astype(str).apply(lambda x: fpe_encrypt_or_decrypt(x, operation, charset=charset))
  return pandas_udf(_series_fn, returnType=StringType())

fpe_encrypt_alpha = make_fpe_pandas_udf("ALPHA", "ENCRYPT")
fpe_decrypt_alpha = make_fpe_pandas_udf("ALPHA", "DECRYPT")
fpe_encrypt_numeric = make_fpe_pandas_udf("NUMERIC", "ENCRYPT")
fpe_decrypt_numeric = make_fpe_pandas_udf("NUMERIC", "DECRYPT")
fpe_encrypt_alphanumeric = make_fpe_pandas_udf("ALPHANUMERIC", "ENCRYPT")
fpe_decrypt_alphanumeric = make_fpe_pandas_udf("ALPHANUMERIC", "DECRYPT")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 5: Encrypt the data with FPE

# COMMAND ----------

from pyspark.sql.functions import col, cast

# Encrypt our data using charset-specific UDFs where we know the column type.
# This ensures correct round-trip encryption for all columns, including alpha-only ones like names.
encrypted = (df
  .select(
    fpe_encrypt_alpha(col("name")).alias("encrypted_name"),
    fpe_encrypt_pandas_udf(col("email")).alias("encrypted_email"),
    fpe_encrypt_numeric(col("date_of_birth").cast("string")).alias("encrypted_date_of_birth"),
    fpe_encrypt_numeric(col("ssn")).alias("encrypted_ssn"),
    fpe_encrypt_numeric(col("ipv4")).alias("encrypted_ipv4"),
    fpe_encrypt_pandas_udf(col("ipv6")).alias("encrypted_ipv6"),
    fpe_encrypt_pandas_udf(col("mac_address")).alias("encrypted_mac_address"),
    fpe_encrypt_pandas_udf(col("phone_number")).alias("encrypted_phone_number"),
    fpe_encrypt_alphanumeric(col("iban")).alias("encrypted_iban"),
    fpe_encrypt_numeric(col("credit_card").cast("string")).alias("encrypted_credit_card"),
    fpe_encrypt_pandas_udf(col("address").cast("string")).alias("encrypted_address")
  ))
display(encrypted)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 6: Decrypt the data with FPE

# COMMAND ----------

# Decrypt our data using the SAME charset-specific UDFs as encryption...
decrypted = (encrypted
  .select(
    fpe_decrypt_alpha(col("encrypted_name")).alias("decrypted_name"),
    fpe_decrypt_pandas_udf(col("encrypted_email")).alias("decrypted_email"),
    fpe_decrypt_numeric(col("encrypted_date_of_birth").cast("string")).alias("decrypted_date_of_birth"),
    fpe_decrypt_numeric(col("encrypted_ssn")).alias("decrypted_ssn"),
    fpe_decrypt_numeric(col("encrypted_ipv4")).alias("decrypted_ipv4"),
    fpe_decrypt_pandas_udf(col("encrypted_ipv6")).alias("decrypted_ipv6"),
    fpe_decrypt_pandas_udf(col("encrypted_mac_address")).alias("decrypted_mac_address"),
    fpe_decrypt_pandas_udf(col("encrypted_phone_number")).alias("decrypted_phone_number"),
    fpe_decrypt_alphanumeric(col("encrypted_iban")).alias("decrypted_iban"),
    fpe_decrypt_numeric(col("encrypted_credit_card")).cast("long").alias("decrypted_credit_card"),
    fpe_decrypt_pandas_udf(col("encrypted_address").cast("string")).alias("decrypted_address")
  ))
display(decrypted)

# COMMAND ----------

display(df.select("name", "email", "date_of_birth", "ssn", "ipv4", "ipv6", "mac_address", "phone_number", "iban", "credit_card", "address"))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 7: Register as Unity Catalog SQL functions
# MAGIC
# MAGIC For production use, you can register FPE as UC SQL functions that inject the encryption key and tweak
# MAGIC from Databricks secrets. This separates key management from the encryption logic.
# MAGIC
# MAGIC First, create a private Python UDF that does the actual encryption/decryption, then wrap it with
# MAGIC public SQL UDFs that inject the secrets. See https://github.com/stikkireddy/python-fpe-cryptography
# MAGIC for the full UC function definitions.
# MAGIC
# MAGIC ```sql
# MAGIC -- Step 1: Create the private Python UDF (see sql/01_python_udf.sql in the repo above)
# MAGIC -- Step 2: Create public SQL wrapper that injects secrets:
# MAGIC
# MAGIC CREATE OR REPLACE FUNCTION encrypt_fpe(text STRING)
# MAGIC RETURNS STRING
# MAGIC DETERMINISTIC
# MAGIC LANGUAGE SQL
# MAGIC RETURN SELECT _encrypt_decrypt_fpe(
# MAGIC     key => secret('fpe_scope', 'fpe_key'),
# MAGIC     tweak => secret('fpe_scope', 'fpe_tweak'),
# MAGIC     text => text,
# MAGIC     operation => "ENCRYPT"
# MAGIC );
# MAGIC
# MAGIC CREATE OR REPLACE FUNCTION decrypt_fpe(text STRING)
# MAGIC RETURNS STRING
# MAGIC DETERMINISTIC
# MAGIC LANGUAGE SQL
# MAGIC RETURN SELECT _encrypt_decrypt_fpe(
# MAGIC     key => secret('fpe_scope', 'fpe_key'),
# MAGIC     tweak => secret('fpe_scope', 'fpe_tweak'),
# MAGIC     text => text,
# MAGIC     operation => "DECRYPT"
# MAGIC );
# MAGIC ```

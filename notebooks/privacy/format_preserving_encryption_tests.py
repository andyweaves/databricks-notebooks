# Databricks notebook source
# MAGIC %pip install -q ff3-cryptography

# COMMAND ----------

# MAGIC %md
# MAGIC ## FPE Test Suite
# MAGIC
# MAGIC Tests for format-preserving encryption. Run this notebook to validate the FPE logic,
# MAGIC including bug fixes for reassemble bounds checking, charset selection, and special char handling.
# MAGIC
# MAGIC Uses the built-in `unittest` framework with a Databricks-friendly runner that displays results inline.

# COMMAND ----------

import unittest
import secrets
import re

from ff3_cryptography.algo import FF3Cipher

# Fixed key and tweak for deterministic tests
KEY = "55bd9c16d82731fb15057fcb4bd10dddd385d679927355cec976dc1f956f0559"
TWEAK = "e333ac1b0ae092"

# COMMAND ----------

# MAGIC %md
# MAGIC ### Setup: import the FPE functions under test
# MAGIC
# MAGIC We re-declare the functions here with explicit key/tweak parameters so the tests are
# MAGIC self-contained and don't depend on notebook cell execution order.

# COMMAND ----------

SPECIAL_CHAR_MODE = "REASSEMBLE"

NUMERIC_CHARSET = "0123456789"
ALPHA_CHARSET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHA_CHARSET_LOWER = "abcdefghijklmnopqrstuvwxyz"
ALPHA_CHARSET_ALL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHANUMERIC_CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
ASCII_CHARSET = """0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c"""
SPECIAL_CHARSET = """!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ """

CHARSET_MAP = {
  "NUMERIC": NUMERIC_CHARSET,
  "ALPHA_UPPER": ALPHA_CHARSET_UPPER,
  "ALPHA_LOWER": ALPHA_CHARSET_LOWER,
  "ALPHA": ALPHA_CHARSET_ALL,
  "ALPHANUMERIC": ALPHANUMERIC_CHARSET,
  "ASCII": ASCII_CHARSET,
}

def reassemble_string(input_str: str, positions: list, characters: str) -> str:
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

def encrypt_or_decrypt(text: str, charset: str, operation: str, key: str = KEY, tweak: str = TWEAK) -> str:
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
  if text.isnumeric():
    return NUMERIC_CHARSET
  elif text.isalnum():
    return ALPHANUMERIC_CHARSET
  else:
    raise ValueError(f"text: {text} should be either numeric or alphanumeric")

def fpe_encrypt_or_decrypt(text: str, operation: str, charset: str = None, key: str = KEY, tweak: str = TWEAK) -> str:
  if len(text) < 6:
    raise ValueError(f"Input string length {len(text)} is not within minimum bounds: 6")
  if len(text) >= 47:
    raise ValueError(f"Input length {len(text)} is not within max bounds of: 47")

  if charset is not None:
    if charset not in CHARSET_MAP:
      raise ValueError(f"Unknown charset '{charset}'. Must be one of: {list(CHARSET_MAP.keys())}")
    resolved_charset = CHARSET_MAP[charset]
    if not text.isascii():
      raise ValueError(f"Input text contains non-ASCII characters")
    if all(c in resolved_charset for c in text):
      return encrypt_or_decrypt(text, resolved_charset, operation, key, tweak)
    extract_special_chars = lambda string: ([char for char in re.findall(r"[^a-zA-Z0-9]", string)], [i for i, char in enumerate(string) if char in SPECIAL_CHARSET])
    characters, positions = extract_special_chars(text)
    removed = re.sub("([^a-zA-Z0-9])", "", text)
    encrypted_decrypted = encrypt_or_decrypt(removed, resolved_charset, operation, key, tweak)
    return reassemble_string(encrypted_decrypted, positions, characters)

  if text.isnumeric():
    return encrypt_or_decrypt(text, NUMERIC_CHARSET, operation, key, tweak)
  elif text.isalnum():
    return encrypt_or_decrypt(text, ALPHANUMERIC_CHARSET, operation, key, tweak)
  elif text.isascii():
    if SPECIAL_CHAR_MODE == "TOKENIZE":
      return encrypt_or_decrypt(text, ASCII_CHARSET, operation, key, tweak)
    elif SPECIAL_CHAR_MODE == "REASSEMBLE":
      extract_special_chars = lambda string: ([char for char in re.findall(r"[^a-zA-Z0-9]", string)], [i for i, char in enumerate(string) if char in SPECIAL_CHARSET])
      characters, positions = extract_special_chars(text)
      removed = re.sub("([^a-zA-Z0-9])", "", text)
      detected_charset = _auto_detect_charset(removed)
      encrypted_decrypted = encrypt_or_decrypt(removed, detected_charset, operation, key, tweak)
      reassembled = reassemble_string(encrypted_decrypted, positions, characters)
      return reassembled
    else:
      raise NotImplementedError("Invalid option - must be 'TOKENIZE' or 'REASSEMBLE'")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Test 1: Basic round-trip encryption/decryption

# COMMAND ----------

class TestBasicRoundTrip(unittest.TestCase):
  """Encrypt then decrypt should return the original plaintext."""

  def test_numeric(self):
    plaintext = "1234567890"
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT")
    self.assertEqual(dt, plaintext)
    self.assertNotEqual(ct, plaintext)

  def test_alphanumeric(self):
    plaintext = "Hello123World"
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT")
    self.assertEqual(dt, plaintext)
    self.assertNotEqual(ct, plaintext)

  def test_ssn_format(self):
    plaintext = "123-45-6789"
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT")
    self.assertEqual(dt, plaintext)
    # Dashes should be preserved in the same positions
    self.assertEqual(ct[3], "-")
    self.assertEqual(ct[6], "-")

  def test_ipv4_format(self):
    plaintext = "192.168.001.001"
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT")
    self.assertEqual(dt, plaintext)
    # Dots should be preserved
    self.assertEqual(ct[3], ".")
    self.assertEqual(ct[7], ".")
    self.assertEqual(ct[11], ".")

  def test_email_format(self):
    plaintext = "testuser@example.com"
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT")
    self.assertEqual(dt, plaintext)
    # @ and . should be at original positions
    self.assertEqual(ct[8], "@")
    self.assertEqual(ct[16], ".")

  def test_with_random_keys(self):
    """Round-trip works with freshly generated keys."""
    k = secrets.token_bytes(32).hex()
    t = secrets.token_bytes(7).hex()
    plaintext = "9876543210"
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", key=k, tweak=t)
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT", key=k, tweak=t)
    self.assertEqual(dt, plaintext)

suite = unittest.TestLoader().loadTestsFromTestCase(TestBasicRoundTrip)
runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)
assert result.wasSuccessful(), f"{len(result.failures)} test(s) failed"

# COMMAND ----------

# MAGIC %md
# MAGIC ### Test 2: Explicit charset round-trip (fixes issue #4)

# COMMAND ----------

class TestExplicitCharset(unittest.TestCase):
  """Explicit charset parameter ensures correct round-trip for all character types."""

  def test_alpha_only_with_explicit_charset(self):
    """This is the key fix: alpha-only text round-trips correctly with charset='ALPHA'."""
    plaintext = "JohnSmith"
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", charset="ALPHA")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT", charset="ALPHA")
    self.assertEqual(dt, plaintext)
    # Ciphertext should only contain alpha characters
    self.assertTrue(ct.isalpha(), f"Expected alpha-only ciphertext, got: {ct}")

  def test_alpha_upper_explicit(self):
    plaintext = "JOHNDOE"
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", charset="ALPHA_UPPER")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT", charset="ALPHA_UPPER")
    self.assertEqual(dt, plaintext)
    self.assertTrue(ct.isupper(), f"Expected uppercase ciphertext, got: {ct}")

  def test_alpha_lower_explicit(self):
    plaintext = "helloworld"
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", charset="ALPHA_LOWER")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT", charset="ALPHA_LOWER")
    self.assertEqual(dt, plaintext)
    self.assertTrue(ct.islower(), f"Expected lowercase ciphertext, got: {ct}")

  def test_numeric_explicit(self):
    plaintext = "5551234567"
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", charset="NUMERIC")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT", charset="NUMERIC")
    self.assertEqual(dt, plaintext)
    self.assertTrue(ct.isnumeric(), f"Expected numeric ciphertext, got: {ct}")

  def test_alphanumeric_explicit(self):
    plaintext = "User1234AB"
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", charset="ALPHANUMERIC")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT", charset="ALPHANUMERIC")
    self.assertEqual(dt, plaintext)

  def test_alpha_name_with_space(self):
    """Name with space: explicit ALPHA charset + REASSEMBLE preserves the space and alpha format."""
    plaintext = "John Smith"
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", charset="ALPHA")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT", charset="ALPHA")
    self.assertEqual(dt, plaintext)
    self.assertEqual(ct[4], " ", "Space should be preserved at position 4")
    core = ct.replace(" ", "")
    self.assertTrue(core.isalpha(), f"Expected alpha-only core, got: {core}")

  def test_alpha_auto_detect_may_not_preserve_alpha(self):
    """Demonstrates the issue: auto-detect uses ALPHANUMERIC for alpha input, so ciphertext may contain digits."""
    plaintext = "JohnSmith"
    ct_auto = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT")  # auto-detect
    ct_explicit = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", charset="ALPHA")
    # Auto-detect still round-trips (both sides use ALPHANUMERIC)
    dt_auto = fpe_encrypt_or_decrypt(ct_auto, "DECRYPT")
    self.assertEqual(dt_auto, plaintext)
    # But explicit gives format-preserving alpha output
    self.assertTrue(ct_explicit.isalpha())

  def test_invalid_charset_raises(self):
    with self.assertRaises(ValueError) as ctx:
      fpe_encrypt_or_decrypt("HelloWorld", "ENCRYPT", charset="INVALID")
    self.assertIn("Unknown charset", str(ctx.exception))

suite = unittest.TestLoader().loadTestsFromTestCase(TestExplicitCharset)
runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)
assert result.wasSuccessful(), f"{len(result.failures)} test(s) failed"

# COMMAND ----------

# MAGIC %md
# MAGIC ### Test 3: Reassemble string bug fix

# COMMAND ----------

class TestReassembleString(unittest.TestCase):
  """Tests for the fixed reassemble_string function."""

  def test_basic_reassembly(self):
    self.assertEqual(reassemble_string("abcdef", [3], ["-"]), "abc-def")

  def test_multiple_special_chars(self):
    self.assertEqual(reassemble_string("123456789", [3, 6], ["-", "-"]), "123-456-789")

  def test_special_char_at_end(self):
    """Position == string length should append."""
    self.assertEqual(reassemble_string("abcdef", [6], ["!"]), "abcdef!")

  def test_adjacent_special_chars(self):
    self.assertEqual(reassemble_string("abcd", [2, 3], [".", "."]), "ab..cd")

  def test_out_of_bounds_raises(self):
    with self.assertRaises(ValueError) as ctx:
      reassemble_string("abc", [10], ["-"])
    self.assertIn("out of bounds", str(ctx.exception))

  def test_mismatched_lengths_raises(self):
    with self.assertRaises(AssertionError):
      reassemble_string("abc", [1, 2], ["-"])

  def test_empty_positions(self):
    self.assertEqual(reassemble_string("hello", [], []), "hello")

  def test_ssn_pattern(self):
    """Simulates SSN: strip dashes from 123-45-6789, encrypt digits, reassemble."""
    self.assertEqual(reassemble_string("encrypted9", [3, 6], ["-", "-"]), "enc-ryp-ted9")

suite = unittest.TestLoader().loadTestsFromTestCase(TestReassembleString)
runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)
assert result.wasSuccessful(), f"{len(result.failures)} test(s) failed"

# COMMAND ----------

# MAGIC %md
# MAGIC ### Test 4: Input validation

# COMMAND ----------

class TestInputValidation(unittest.TestCase):

  def test_min_length(self):
    with self.assertRaises(ValueError) as ctx:
      fpe_encrypt_or_decrypt("short", "ENCRYPT")
    self.assertIn("minimum bounds", str(ctx.exception))

  def test_min_length_boundary(self):
    # length 6 should work
    result = fpe_encrypt_or_decrypt("123456", "ENCRYPT")
    self.assertIsNotNone(result)

  def test_max_length(self):
    with self.assertRaises(ValueError) as ctx:
      fpe_encrypt_or_decrypt("a" * 47, "ENCRYPT", charset="ALPHA")
    self.assertIn("max bounds", str(ctx.exception))

  def test_max_length_boundary(self):
    # length 46 should work
    plaintext = "a" * 46
    result = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", charset="ALPHA")
    self.assertIsNotNone(result)

  def test_invalid_operation(self):
    with self.assertRaises(NotImplementedError):
      encrypt_or_decrypt("1234567890", NUMERIC_CHARSET, "INVALID")

suite = unittest.TestLoader().loadTestsFromTestCase(TestInputValidation)
runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)
assert result.wasSuccessful(), f"{len(result.failures)} test(s) failed"

# COMMAND ----------

# MAGIC %md
# MAGIC ### Test 5: Special character handling

# COMMAND ----------

class TestSpecialCharHandling(unittest.TestCase):

  def test_underscore_treated_as_special(self):
    """Regression: old regex [^\\w] did not treat underscore as special. Fixed to [^a-zA-Z0-9]."""
    plaintext = "hello_world_test"
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT")
    self.assertEqual(dt, plaintext)
    self.assertEqual(ct[5], "_")
    self.assertEqual(ct[11], "_")

  def test_mac_address_format(self):
    plaintext = "00:1B:44:11:3A:B7"
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT")
    self.assertEqual(dt, plaintext)
    for pos in [2, 5, 8, 11, 14]:
      self.assertEqual(ct[pos], ":", f"Colon missing at position {pos}")

  def test_phone_number_format(self):
    plaintext = "+1-555-867-5309"
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT")
    self.assertEqual(dt, plaintext)
    self.assertEqual(ct[0], "+")
    self.assertEqual(ct[2], "-")

  def test_multiple_special_char_types(self):
    plaintext = "user.name@host.com"
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT")
    self.assertEqual(dt, plaintext)
    self.assertEqual(ct[4], ".")
    self.assertEqual(ct[9], "@")
    self.assertEqual(ct[14], ".")

  def test_explicit_numeric_with_separators(self):
    """Numeric charset with dashes: digits encrypted, dashes preserved."""
    plaintext = "123-456-7890"
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", charset="NUMERIC")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT", charset="NUMERIC")
    self.assertEqual(dt, plaintext)
    core = ct.replace("-", "")
    self.assertTrue(core.isnumeric(), f"Expected numeric core, got: {core}")

suite = unittest.TestLoader().loadTestsFromTestCase(TestSpecialCharHandling)
runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)
assert result.wasSuccessful(), f"{len(result.failures)} test(s) failed"

# COMMAND ----------

# MAGIC %md
# MAGIC ### Test 6: Long string chunking (> 28 chars)

# COMMAND ----------

class TestLongStringChunking(unittest.TestCase):
  """FF3 has a max block size, so strings > 28 chars are split into chunks."""

  def test_long_numeric(self):
    plaintext = "12345678901234567890123456789012"  # 32 digits
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", charset="NUMERIC")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT", charset="NUMERIC")
    self.assertEqual(dt, plaintext)
    self.assertEqual(len(ct), len(plaintext))

  def test_long_alphanumeric(self):
    plaintext = "abcdefghij1234567890ABCDEFGHIJ12"  # 32 chars
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", charset="ALPHANUMERIC")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT", charset="ALPHANUMERIC")
    self.assertEqual(dt, plaintext)
    self.assertEqual(len(ct), len(plaintext))

  def test_long_alpha(self):
    plaintext = "abcdefghijklmnopqrstuvwxyzABCDEF"  # 32 chars
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", charset="ALPHA")
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT", charset="ALPHA")
    self.assertEqual(dt, plaintext)
    self.assertTrue(ct.isalpha())

  def test_length_preserved(self):
    """Ciphertext must always be the same length as plaintext."""
    for length in [6, 10, 20, 28, 29, 35, 46]:
      plaintext = "a" * length
      ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", charset="ALPHA_LOWER")
      self.assertEqual(len(ct), length, f"Length mismatch for input length {length}")

suite = unittest.TestLoader().loadTestsFromTestCase(TestLongStringChunking)
runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)
assert result.wasSuccessful(), f"{len(result.failures)} test(s) failed"

# COMMAND ----------

# MAGIC %md
# MAGIC ### Test 7: Deterministic encryption

# COMMAND ----------

class TestDeterministic(unittest.TestCase):
  """Same key + tweak + plaintext should always produce the same ciphertext."""

  def test_same_output_each_time(self):
    plaintext = "1234567890"
    ct1 = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT")
    ct2 = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT")
    self.assertEqual(ct1, ct2)

  def test_different_keys_different_output(self):
    plaintext = "1234567890"
    k1 = secrets.token_bytes(32).hex()
    k2 = secrets.token_bytes(32).hex()
    t = TWEAK
    ct1 = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", key=k1, tweak=t)
    ct2 = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", key=k2, tweak=t)
    self.assertNotEqual(ct1, ct2)

  def test_different_tweaks_different_output(self):
    plaintext = "1234567890"
    k = KEY
    t1 = secrets.token_bytes(7).hex()
    t2 = secrets.token_bytes(7).hex()
    ct1 = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", key=k, tweak=t1)
    ct2 = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", key=k, tweak=t2)
    self.assertNotEqual(ct1, ct2)

suite = unittest.TestLoader().loadTestsFromTestCase(TestDeterministic)
runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)
assert result.wasSuccessful(), f"{len(result.failures)} test(s) failed"

# COMMAND ----------

# MAGIC %md
# MAGIC ### Test 8: Realistic PII round-trip scenarios

# COMMAND ----------

class TestRealisticPII(unittest.TestCase):
  """End-to-end tests with realistic PII values."""

  def _round_trip(self, plaintext, charset=None):
    ct = fpe_encrypt_or_decrypt(plaintext, "ENCRYPT", charset=charset)
    dt = fpe_encrypt_or_decrypt(ct, "DECRYPT", charset=charset)
    self.assertEqual(dt, plaintext, f"Round-trip failed for '{plaintext}' (charset={charset})")
    self.assertEqual(len(ct), len(plaintext), f"Length changed for '{plaintext}'")
    return ct

  def test_names(self):
    for name in ["John Smith", "Jane O'Brien", "Mary-Jane Watson"]:
      if all(c.isalpha() or c in SPECIAL_CHARSET for c in name):
        self._round_trip(name, charset="ALPHA")

  def test_ssns(self):
    for ssn in ["123-45-6789", "987-65-4321", "555-12-3456"]:
      ct = self._round_trip(ssn, charset="NUMERIC")
      self.assertTrue(ct.replace("-", "").isnumeric())

  def test_credit_cards(self):
    for cc in ["4111111111111111", "5500000000000004"]:
      ct = self._round_trip(cc, charset="NUMERIC")
      self.assertTrue(ct.isnumeric())

  def test_dates(self):
    for d in ["2024-01-15", "1990-12-31"]:
      ct = self._round_trip(d, charset="NUMERIC")
      self.assertEqual(ct[4], "-")
      self.assertEqual(ct[7], "-")

  def test_ipv4(self):
    for ip in ["192.168.001.001", "010.000.000.001"]:
      ct = self._round_trip(ip, charset="NUMERIC")
      self.assertEqual(ct.count("."), 3)

  def test_ibans(self):
    for iban in ["GB29NWBK60161331926819", "DE89370400440532013000"]:
      self._round_trip(iban, charset="ALPHANUMERIC")

suite = unittest.TestLoader().loadTestsFromTestCase(TestRealisticPII)
runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)
assert result.wasSuccessful(), f"{len(result.failures)} test(s) failed"

# COMMAND ----------

# MAGIC %md
# MAGIC ### Summary
# MAGIC
# MAGIC If all cells above completed without assertion errors, all tests passed.
# MAGIC
# MAGIC | Test Suite | What it covers |
# MAGIC |---|---|
# MAGIC | BasicRoundTrip | Core encrypt/decrypt for numeric, alphanumeric, SSN, IPv4, email |
# MAGIC | ExplicitCharset | **Issue #4 fix** - alpha-only round-trips with explicit charset param |
# MAGIC | ReassembleString | **Bug fix** - bounds checking, edge cases in special char reinsertion |
# MAGIC | InputValidation | Min/max length guards, invalid operation |
# MAGIC | SpecialCharHandling | **Regex fix** - underscore, MAC address, phone, email separators |
# MAGIC | LongStringChunking | Strings > 28 chars split into FF3 blocks correctly |
# MAGIC | Deterministic | Same inputs = same outputs, different keys = different outputs |
# MAGIC | RealisticPII | End-to-end with real-world PII formats |

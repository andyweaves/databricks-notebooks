# Common Crypto Utilities

Shared modules used by all envelope encryption v2 backends.

## Modules

### `pycrypto_functions.py`

- `generate_kek()` -- Generates a KEK password and salt using `secrets.token_bytes` and `pycryptodome`.
- `generate_dek(with_iv_aad=False)` -- Generates a DEK (and optionally an IV and AAD) using `secrets.token_bytes`.
- `encrypt_with_kek(kek_password, kek_salt, to_encrypt)` -- Encrypts a string with a KEK using AES-GCM via scrypt key derivation. Returns the ciphertext, nonce, and authentication tag.
- `decrypt_with_kek(kek_password, kek_salt, to_decrypt, nonce, tag)` -- Decrypts and verifies a string encrypted by `encrypt_with_kek`.
- `create_aws_secret(session, ...)` / `get_aws_secret(session, ...)` / `put_aws_secret(session, ...)` -- AWS Secrets Manager helpers for storing and retrieving secrets.

### `aws_crypto_functions.py`

- `create_kms_key(session, alias, description, tags)` -- Creates an AWS KMS symmetric CMK and alias.
- `generate_data_key(session, key_alias, encryption_context)` -- Generates an AES-256 data key encrypted under the specified KMS CMK.

Both modules raise exceptions on failure (with contextual notes where applicable) rather than returning error objects.

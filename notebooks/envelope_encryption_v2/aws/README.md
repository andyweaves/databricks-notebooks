# AWS Envelope Encryption Backends

Two AWS-backed variants for envelope encryption with Unity Catalog.

## KMS (`kms/`)

Uses **AWS KMS** directly to manage the key hierarchy. A symmetric Customer Master Key (CMK) is created in KMS, and KMS generates encrypted data keys (DEKs) via `GenerateDataKey`. The encrypted DEKs are stored in a `crypto.keyvault` Unity Catalog table. Decryption calls KMS to unwrap the DEK at query time via a batch Python UDF.

**Notebooks**: `01_setup.ipynb` (admin setup), `02_user.ipynb` (user verification), `03_new_dek.ipynb` (DEK rotation).

**Required IAM permissions** on the UC service credential: `kms:CreateKey`, `kms:CreateAlias`, `kms:GenerateDataKey`, `kms:Decrypt`.

## Secrets Manager (`secrets_manager/`)

Uses **AWS Secrets Manager** to store both the KEK and encrypted DEKs as a single JSON secret. The KEK is generated locally with pycryptodome and used to wrap DEKs via AES-GCM with scrypt key derivation. At query time, a batch Python UDF retrieves the secret from Secrets Manager and unwraps the DEK in-memory.

**Notebooks**: `01_setup.ipynb` (admin setup), `02_user.sql` (user verification), `03_rotate_kek.ipynb` (KEK rotation), `04_new_dek.ipynb` (new DEK for additional schemas).

**Required IAM permissions** on the UC service credential: `secretsmanager:CreateSecret`, `secretsmanager:GetSecretValue`, `secretsmanager:PutSecretValue`, `secretsmanager:ListSecrets`.

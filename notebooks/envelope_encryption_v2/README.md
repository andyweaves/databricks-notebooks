# Envelope Encryption v2

Version 2 extends the [v1 envelope encryption pattern](../envelope_encryption/) by integrating with **cloud-native KMS services** instead of storing keys solely within Databricks. KEKs are managed by the cloud provider (AWS KMS, AWS Secrets Manager, or Azure Key Vault), providing hardware-backed key protection, audit logging, and centralized key lifecycle management.

## What v2 Adds Over v1

- Cloud KMS integration for KEK management (keys never leave the cloud provider)
- Unity Catalog **service credentials** for secure cross-cloud authentication
- Support for multiple cloud backends
- Batch Python UDFs with executor-local caching for efficient key unwrapping
- Account-group-based access control via `<catalog>.<schema>.crypto.user` groups

## Supported Backends

| Backend | Directory | KEK Storage | DEK Storage |
|---|---|---|---|
| AWS KMS | `aws/kms/` | AWS KMS (symmetric CMK) | `crypto.keyvault` UC table (encrypted by KMS) |
| AWS Secrets Manager | `aws/secrets_manager/` | AWS Secrets Manager (with pycryptodome KEK wrapping) | AWS Secrets Manager (as secret values) |
| Azure Key Vault | `azure/akv/` | Azure Key Vault (RSA key) | `crypto.keyvault` UC table (wrapped by AKV) |

## Directory Structure

```
envelope_encryption_v2/
  common/              Shared crypto utility modules
    pycrypto_functions.py    KEK/DEK generation, AES-GCM encrypt/decrypt, AWS Secrets Manager helpers
    aws_crypto_functions.py  AWS KMS key creation, data key generation
  aws/
    kms/               AWS KMS variant (3 notebooks)
    secrets_manager/   AWS Secrets Manager variant (4 notebooks)
  azure/
    akv/               Azure Key Vault variant (2 notebooks)
  requirements.txt     Python dependencies (pycryptodome, azure-keyvault-keys, azure-identity)
```

## How to Run Each Variant

Each variant follows the same general pattern: run the setup notebook first, then use the user notebook to verify. See the README in each subdirectory for specifics.

- **AWS KMS**: `aws/kms/01_setup.ipynb` then `02_user.ipynb`. Use `03_new_dek.ipynb` for DEK rotation.
- **AWS Secrets Manager**: `aws/secrets_manager/01_setup.ipynb` then `02_user.sql`. Use `03_rotate_kek.ipynb` for KEK rotation and `04_new_dek.ipynb` for DEK rotation.
- **Azure Key Vault**: `azure/akv/01_setup.ipynb` then `02_user.ipynb`.

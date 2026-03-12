# Envelope Encryption (v1)

Envelope encryption is a hierarchical key management pattern where a **Key Encryption Key (KEK)** protects one or more **Data Encryption Keys (DEKs)**. The DEK encrypts/decrypts the actual data, while the KEK encrypts/decrypts the DEK. This separation means rotating the KEK does not require re-encrypting all data -- only the DEK needs to be re-wrapped.

## Notebooks

Run the notebooks in order:

1. **`1 - keyvault_admin_setup.py`** -- Admin setup that generates a KEK, stores it in a `sys.crypto.key_vault` table, creates an encrypted DEK stored as a Databricks secret, builds `encrypt()`/`decrypt()` Unity Catalog functions, encrypts a sample table, and applies column masks.
2. **`2 - keyvault_user.sql`** -- User verification notebook that confirms an unprivileged user (member of `keyvault_user` group) can read decrypted data via column masks but cannot access the key vault, raw data, or crypto functions directly.
3. **`3 - keyvault_admin_rotation.py`** -- Admin key rotation that generates a new KEK, re-encrypts the DEK under the new KEK, updates the secret and key vault table, and verifies decryption still works.

## Prerequisites

- Databricks workspace with Unity Catalog enabled
- A secret scope (provided as a widget parameter)
- An account-level group called `keyvault_admin` for admin access
- An account-level group called `keyvault_user` for end-user decrypt access
- Permissions to create catalogs/schemas/tables/functions in Unity Catalog

## How to Run

1. Run **notebook 1** as an admin to set up the KEK, DEK, crypto functions, and encrypted table. Provide values for the `secret_scope`, `kek_name`, and `keyvault_user` widgets.
2. Run **notebook 2** as the unprivileged user specified in step 1 to verify access controls. Provide the same `secret_scope`.
3. Run **notebook 3** as an admin when you need to rotate the KEK. Provide the same `secret_scope` and `kek_name`.

# Azure Key Vault Envelope Encryption Backend

Uses **Azure Key Vault (AKV)** to manage the key hierarchy. An RSA key is created in Key Vault to serve as the KEK, and a locally generated DEK is wrapped (encrypted) using RSA-OAEP-256. The wrapped DEK is stored in a `crypto.keyvault` Unity Catalog table. At query time, a batch Python UDF calls AKV to unwrap the DEK, with executor-local caching to minimize API calls.

## Notebooks

- `akv/01_setup.ipynb` -- Admin setup: creates the AKV RSA key, generates and wraps a DEK, stores it in the keyvault table, creates `unwrap_akv_key()`/`encrypt()`/`decrypt()` UDFs, encrypts a sample table, and applies column masks.
- `akv/02_user.ipynb` -- User verification: confirms that members of the `<catalog>.<schema>.crypto.user` group can read decrypted data via column masks.

## Prerequisites

- An Azure Key Vault instance with the URL provided as a widget parameter
- A Unity Catalog service credential with Key Vault Crypto Officer (for key creation) and Crypto User (for wrap/unwrap) permissions
- Python packages: `azure-keyvault-keys`, `azure-identity` (install via `requirements.txt` or pre-loaded wheels)
- Network connectivity from serverless compute to the Key Vault (via Private Link or egress policy)

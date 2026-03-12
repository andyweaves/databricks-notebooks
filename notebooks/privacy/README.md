# notebooks/privacy

Databricks notebooks for detecting, tagging, and protecting PII in Unity Catalog.

## Notebooks

### identifying_and_tagging_pii.py

Scans Unity Catalog tables for PII using Microsoft Presidio and automatically applies tags and comments to flag sensitive data.

- Presents widget selectors for catalogs, entity types, and language.
- Broadcasts a Presidio `AnalyzerEngine` across the Spark cluster.
- Enumerates all tables in selected catalogs via `system.information_schema.tables`.
- Scans each table using `PIIScanner` with a thread pool (capped at 8 workers).
- Applies Unity Catalog tags (e.g., `PII`, `EMAIL_ADDRESS`, `US_SSN`) and markdown comments to tables and columns where PII is detected.

### format_preserving_encryption.py

Demonstrates format-preserving encryption (FPE) using the FF3-1 algorithm, which encrypts data while preserving its original format and length.

- Generates fake PII data, then encrypts selected columns (name, email, SSN, IP addresses, etc.).
- Supports multiple character sets (numeric, alpha, alphanumeric, ASCII).
- Handles special characters via two modes: `TOKENIZE` (encrypt everything) or `REASSEMBLE` (preserve special character positions).
- Decrypts the data back to verify round-trip correctness.

### information_schema_pii_tags.sql

Queries Unity Catalog's information schema to report on PII access. Creates temporary views that join PII tags with privilege grants to answer:

- Which tables, schemas, and catalogs are tagged with PII?
- Which users and groups have access to PII-tagged securables?
- Which principals are most privileged across PII data?

## Prerequisites

- **Pip packages**: Installed automatically via `%pip install -q -r ../../requirements.txt` at the top of each Python notebook. Key packages include `presidio_analyzer`, `presidio_anonymizer`, `faker`, `mimesis`, and `ff3` (for FPE).
- **spaCy model**: `identifying_and_tagging_pii.py` downloads `en_core_web_lg` at startup.
- **Unity Catalog access**: The scanning and tagging notebooks require access to `system.information_schema` and `ALTER` permissions on target securables.
- **Databricks secrets** (recommended for FPE): The encryption notebook generates ephemeral keys by default but should use `dbutils.secrets` in production.

## Running

The three notebooks are independent and can be run in any order. Each is self-contained with its own setup cells.

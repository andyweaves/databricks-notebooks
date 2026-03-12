# common

Shared utility module used across multiple notebooks in this repository.

## privacy_functions.py

Provides reusable functions and classes for PII (Personally Identifiable Information) operations on Databricks.

### What it provides

- **Fake data generation** -- `generate_fake_pii_data()` produces a Spark DataFrame with 30+ columns of realistic fake PII (names, emails, SSNs, credit cards, IBANs, IP addresses, passports, etc.), including struct, map, and array column types.
- **PIIScanner class** -- Scans Spark DataFrames and Unity Catalog tables/views for PII using Microsoft Presidio. It detects entity types (e.g., `EMAIL_ADDRESS`, `US_SSN`, `CREDIT_CARD`), filters results by configurable hit rate and confidence score thresholds, and can automatically apply Unity Catalog tags and comments to flag tables and columns containing PII.
- **Helper utilities** -- `get_selection()` for widget multi-select handling, `all_supported_entities` list of Presidio entity types.

### Key classes and functions

| Name | Description |
|------|-------------|
| `PIIScanner` | Main class for scanning DataFrames/tables for PII and tagging Unity Catalog securables |
| `PIIScanner.get_all_uc_tables()` | Static method that queries `system.information_schema.tables` for all tables in given catalogs |
| `PIIScanner.scan_dataframe()` | Scans a DataFrame for PII entities and returns aggregated results |
| `PIIScanner.scan_and_tag_securable()` | Scans a table/view and applies PII tags and comments in Unity Catalog |
| `generate_fake_pii_data()` | Generates a Spark DataFrame of fake PII data with configurable row count |
| `generate_fake_data()` | Pandas UDF used internally by `generate_fake_pii_data()` |
| `get_selection()` | Resolves "ALL" in widget multi-select values to the full option list |
| `all_supported_entities` | List of all Presidio entity types supported by the scanner |

### Dependencies

- `presidio_analyzer` -- Microsoft Presidio text analytics engine for PII detection
- `presidio_anonymizer` -- Microsoft Presidio anonymization (used downstream)
- `faker` -- Generates fake PII data (US locale)
- `mimesis` -- Additional fake data generation (EN locale)
- `pyspark` -- Spark DataFrames, UDFs, and SQL

### Usage context

This module is imported via `%run ../../common/privacy_functions` by:

- `notebooks/privacy/` -- PII scanning, tagging, and format-preserving encryption notebooks
- `notebooks/fake_pii_data/` -- Fake PII data generation notebook

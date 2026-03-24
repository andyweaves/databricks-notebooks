# notebooks/fake_pii_data

Databricks notebook for generating realistic fake PII test data across multiple locales and writing it to a Unity Catalog table. Designed to scale from thousands to billions of rows.

## generate_fake_pii.py

Generates configurable volumes of fake PII data using `faker` and `mimesis` with 8 locales, then saves the result as a Delta table in Unity Catalog.

### Widget parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `num_rows` | dropdown | `1000` | Number of rows to generate. Options: 1K / 10K / 100K / 1M / 10M / 100M / 1B. |
| `rows_per_partition` | dropdown | `10000` | Rows per Spark partition. Lower values use more parallelism; higher values reduce task overhead. Tune based on cluster size. |
| `locale` | dropdown | `all` | Which locale(s) to use. Select `all` for a random mix across all 8 locales, or pick a single locale (e.g. `ja_JP`). |
| `catalog` | dropdown | First available catalog | Target Unity Catalog catalog (populated dynamically from workspace). |
| `schema` | dropdown | First schema in selected catalog | Target schema within the selected catalog. |
| `table_name` | text | `fake_pii_data_<timestamp>` | Name of the output table. Defaults to a timestamped name to avoid collisions. |

### Scaling guide

| Rows | Suggested `rows_per_partition` | Approximate partitions |
|------|-------------------------------|----------------------|
| 1K–100K | 1,000–5,000 | 1–100 |
| 1M–10M | 10,000 | 100–1,000 |
| 100M–1B | 50,000–100,000 | 2,000–10,000 |

For billion-row runs, use a cluster with autoscaling workers and set `rows_per_partition` to 50,000–100,000 to balance memory usage against task scheduling overhead.

### Locales

Data is generated across 8 locales, randomly assigned per row:

`en_US`, `en_GB`, `de_DE`, `fr_FR`, `ja_JP`, `zh_CN`, `pt_BR`, `es_MX`

Each row's `locale` column records which locale was used, and locale-sensitive fields (names, addresses, national IDs, driver's licenses, phone numbers) reflect that locale's conventions.

### Output format

The notebook produces a table with 27 columns:

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `locale` | string | No | Locale used to generate this row (e.g. `en_US`, `ja_JP`) |
| `name` | string | No | Full person name |
| `email` | string | No | Email address (personal, company, or free provider) |
| `passport` | string | Yes | Passport number or full passport details |
| `phone_number` | string | No | Phone number in locale format |
| `ipv4` | string | No | IPv4 address (may include port) |
| `ipv6` | string | No | IPv6 address |
| `address` | string | No | Full street address |
| `location` | string | No | City, country, state, or street address |
| `national_id` | string | Yes | Locale-appropriate national ID (SSN for US, NI number for UK, etc.) |
| `tax_id` | string | Yes | Tax identification number (ITIN for US, national ID for others, null where N/A) |
| `bank_number` | string | Yes | Bank account or card number |
| `iban` | string | Yes | International Bank Account Number |
| `credit_card_number` | string | No | Credit card number |
| `credit_card_expiry` | string | No | Credit card expiration date |
| `date_of_birth` | string | No | Date of birth (ISO 8601) |
| `age` | integer | No | Age in years |
| `gender` | string | No | Gender or honorific prefix |
| `nationality` | string | No | Nationality or country name |
| `drivers_license` | string | Yes | Driver's license number in locale-appropriate format |
| `medical_record_number` | string | No | Formatted MRN (e.g. `MRN-1234567`) |
| `username` | string | No | Username / handle |
| `password_hash` | string | No | SHA-256 hash of a randomly generated password |
| `mac_address` | string | No | MAC address |
| `user_agent` | string | No | Browser user-agent string |
| `company` | string | No | Company or organization name |
| `job_title` | string | No | Job title or occupation |

### Architecture

- All `faker` and `mimesis` generators are initialized **inside** the `applyInPandas` UDF, so they run on executors without serialization overhead
- Each row is generated independently via list comprehension — every row gets unique values
- `spark.range()` with explicit `numPartitions` controls parallelism, making it straightforward to scale across large clusters
- The `rows_per_partition` widget lets users tune the memory-vs-parallelism trade-off

### Prerequisites

- `faker` and `mimesis` pip packages (installed automatically by the first notebook cell)
- Write access to the target Unity Catalog catalog and schema

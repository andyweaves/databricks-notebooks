# notebooks/fake_pii_data

Databricks notebook for generating realistic fake PII test data and writing it to a Unity Catalog table.

## generate_fake_pii.ipynb

Generates a configurable number of rows of fake PII data using `faker` and `mimesis`, then saves the result as a Delta table in Unity Catalog.

### Widget parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `num_rows` | dropdown | `1000` | Number of rows to generate. Options: 1,000 / 10,000 / 100,000 / 1,000,000. |
| `catalog` | dropdown | First available catalog | Target Unity Catalog catalog (populated dynamically from workspace). |
| `schema` | dropdown | First schema in selected catalog | Target schema within the selected catalog. |
| `table_name` | text | `fake_pii_data_<timestamp>` | Name of the output table. Defaults to a timestamped name to avoid collisions. |

### Output format

The notebook produces a table with 13 PII columns:

| Column | Type | Description |
|--------|------|-------------|
| `name` | string | Full person name |
| `email` | string | Email address |
| `passport` | string | Passport number or full passport details |
| `phone_number` | string | Phone number |
| `ipv4` | string | IPv4 address (may include port) |
| `ipv6` | string | IPv6 address |
| `address` | string | Full street address |
| `location` | string | City, country, state, or street address |
| `ssn` | string | US Social Security Number |
| `itin` | string | US Individual Taxpayer Identification Number |
| `bank_number` | string | Basic Bank Account Number (BBAN) |
| `iban` | string | International Bank Account Number |
| `credit_card_number` | string | Credit card number |

Each column randomly selects from multiple generator functions (faker and mimesis) to produce varied, realistic-looking data.

### Prerequisites

- `faker` and `mimesis` pip packages (installed automatically by the first notebook cell).
- Write access to the target Unity Catalog catalog and schema.

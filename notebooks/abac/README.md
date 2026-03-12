# ABAC: Attribute-Based Access Control

Attribute-Based Access Control (ABAC) uses Unity Catalog tags and column masks to dynamically control access to sensitive data. Rather than managing permissions on individual columns across many tables, ABAC lets you define policies based on column metadata (tags) so that masking rules are automatically applied wherever a tagged column appears.

## How It Works

The approach has three steps:

1. **Tag columns with their PII type.** Each column containing sensitive data is tagged in Unity Catalog with a classification tag (e.g., `class.name`, `class.email_address`, `class.us_ssn`). This is typically done during a PII scanning/tagging process (see the `privacy` notebooks).

2. **Create masking functions.** SQL UDFs are defined that transform a column value into a redacted form. Different PII types get different redaction strategies (full replacement, partial masking, domain-only for emails, etc.).

3. **Create ABAC policies.** Each policy ties a tag to a masking function and specifies which users are subject to the mask. Policies are applied at the catalog level and automatically match any column with the corresponding tag.

## Redaction Functions

| Function | Strategy | Example |
|---|---|---|
| `redact_string` | Full replacement | `John` -> `[REDACTED]` |
| `redact_name` | Full replacement | `Jane Doe` -> `[REDACTED_NAME]` |
| `redact_email` | Strip local part, keep domain | `user@example.com` -> `example.com` |
| `redact_ip_address` | Truncate last octets (IPv4) or last groups (IPv6) | `192.168.1.5` -> `192.168.1.0/24` |
| `redact_substring` | Mask middle characters, keep first and last 2 | `123456789` -> `12XXXXX89` |
| `redact_endstring` | Mask leading characters, keep last 3 | `4111111111111111` -> `XXXXXXXXXXXXX111` |
| `redact_digits` | Replace all digits with `*` | `555-123-4567` -> `***-***-****` |
| `mask_string` | Mask all upper, lower, and numeric characters | `123 Main St` -> `nnn Xxxx Xx` |

## Policies Created

| Policy | Tag | Masking Function |
|---|---|---|
| `redact_name` | `class.name` | `redact_name` |
| `redact_email` | `class.email_address` | `redact_email` |
| `redact_phone_number` | `class.phone_number` | `redact_digits` |
| `redact_ip_address` | `class.ip_address` | `redact_ip_address` |
| `redact_location` | `class.location` | `mask_string` |
| `redact_bank_number` | `class.us_bank_number` | `redact_substring` |
| `redact_ssn` | `class.us_ssn` | `redact_digits` |
| `redact_itin` | `class.us_itin` | `redact_digits` |
| `redact_iban` | `class.iban_code` | `redact_substring` |
| `redact_credit_card` | `class.credit_card` | `redact_endstring` |

## The `pii_viewer` Group

All policies are applied to `account users` **except** members of the `{catalog}.pii_viewer` group. Users in this account-level group will see unmasked data. This provides a simple exception mechanism for authorized personnel (e.g., data stewards, compliance officers) who need access to raw PII.

## Prerequisites

- **Unity Catalog** enabled on your Databricks workspace.
- **Tagged columns.** Columns must already be tagged with the appropriate `class.*` tags (see the `privacy` notebooks for automated PII scanning and tagging).
- **Account-level group.** A `{catalog}.pii_viewer` group must exist as an account-level group before running the notebook. The notebook will raise an error if it is missing.

# Databricks Security & Privacy Notebooks

A collection of Databricks notebooks covering data privacy, encryption, AI/LLM safety guardrails, and security monitoring on the Databricks platform.

## Contents

### Data Privacy (`notebooks/privacy/`)

- **Identifying and Tagging PII** — Scans Unity Catalog tables for PII using [Presidio](https://github.com/microsoft/presidio), then automatically tags columns and tables with detected entity types (SSN, email, credit card, etc.).
- **Format-Preserving Encryption** — Encrypts PII fields using FF3 cipher while preserving the original data format, enabling encrypted data to pass format validations.
- **Information Schema PII Tags** (`SQL`) — Queries to join PII tags with privilege grants, answering "who has access to PII data?"

### Attribute-Based Access Control (`notebooks/abac/`)

Implements ABAC policies using Unity Catalog column masks and row filters. Creates per-PII-type redaction functions (e.g., `redact_email`, `redact_ssn`, `redact_credit_card`) that dynamically mask columns based on tags and group membership.

### Envelope Encryption (`notebooks/envelope_encryption/`, `notebooks/envelope_encryption_v2/`)

Hierarchical key management with Key Encryption Keys (KEK) and Data Encryption Keys (DEK):

- **v1** — Self-managed KEK stored in a `key_vault` table, DEK stored as a Databricks secret. Includes admin setup, user verification, and key rotation notebooks.
- **v2** — Cloud KMS integration with support for:
  - **AWS KMS** — Uses KMS-managed CMKs to generate and wrap DEKs
  - **AWS Secrets Manager** — Stores encrypted DEKs in Secrets Manager with KEK rotation support
  - **Azure Key Vault** — Uses AKV for key wrapping and management

Both versions demonstrate column-level encryption with automatic decryption via column masks for authorized users.

### AI Guardrails (`notebooks/ai_guardrails/`)

Deploy and test safety guardrails for LLM endpoints on Databricks AI Gateway:

- **Llama Guard 3 & 4** — Content moderation across 14 safety categories (violence, hate, CSAM, weapons, etc.). Guard 4 adds vision capabilities with GPU acceleration.
- **Code Shield** — Output guardrail that scans LLM-generated code for security vulnerabilities (SQL injection, command injection, etc.) across 7 languages.
- **Prompt Guard 2** — Input guardrail detecting prompt injection and jailbreak attempts.
- **Red Teaming (BlackIce)** — Automated adversarial testing of model endpoints using [Garak](https://github.com/NVIDIA/garak) with DAN jailbreak probes. Includes alert definitions for monitoring guardrail triggers and egress denials.

### Security Genie (`notebooks/security_genie/`)

An AI-powered security auditing assistant built on Databricks audit logs (`system.access.audit`):

- **ETL** — Materialized view normalizing raw audit logs into a queryable format.
- **Setup** — UDFs for detecting failed authentication attempts and IP ACL violations over 90-day windows.
- **IP ACL Validation** — Checks current IP access control lists against actual traffic to identify unauthorized access attempts.
- **Example Queries** — Ready-to-use security investigation queries: unauthorized access, secret access patterns, Delta Sharing from untrusted networks, Databricks support access, and more.

### Fake PII Data Generator (`notebooks/fake_pii_data/`)

Generates realistic synthetic PII data (names, SSNs, emails, credit cards, IPs, IBANs, etc.) using Faker and Mimesis. Configurable from 1K to 1M rows, saved as Unity Catalog tables for testing privacy and encryption workflows.

### Common Utilities (`common/`)

`privacy_functions.py` — Shared `PIIScanner` class wrapping Presidio for distributed PII detection across Spark DataFrames, with automatic Unity Catalog tagging and commenting.

### Alerts (`sql/alerts/`)

Databricks SQL alert definitions for monitoring serverless compute egress denials.

## Requirements

```
faker
mimesis
ff3
presidio_analyzer
presidio_anonymizer
tabulate
```

Cloud-specific notebooks also require `pycryptodome`, `azure-keyvault-keys`, and `azure-identity` (see `notebooks/envelope_encryption_v2/requirements.txt`).

## License

Apache License 2.0 — see [LICENSE](LICENSE).

# Databricks

A collection of useful Databricks code, notebooks, templates, and apps. Originally focused on security and privacy, now expanding to cover anything that might be useful on the platform.

Each subdirectory has its own README with full detail — the table below is just a jumping-off point.

## Contents

| Directory | What's in it |
|---|---|
| [`apps/`](apps/README.md) | Databricks Apps — including **Amiga Bricks**, a web-based Amiga emulator. |
| [`notebooks/`](notebooks/README.md) | Notebooks organized by topic. Currently focused on security & privacy: PII detection/tagging, ABAC column masks, envelope encryption (AWS/Azure KMS), AI guardrails (Llama Guard, Code Shield, Prompt Guard, red teaming), and a Security Genie for audit log analysis. |
| [`common/`](common/README.md) | Shared Python utilities. `privacy_functions.py` wraps Presidio for distributed PII detection and Unity Catalog tagging. |
| [`sql/`](sql/README.md) | Databricks SQL assets — currently an alert definition for serverless egress denials. |
| [`resources/`](resources/README.md) | Config files referenced by notebooks and apps (e.g. Genie system instructions). |

See each directory's README for setup, usage, and dependencies.

## Requirements

Root `requirements.txt` covers the common notebook dependencies (Faker, Mimesis, FF3, Presidio). Some subprojects ship their own `requirements.txt` — e.g. [`apps/amiga_app/`](apps/amiga_app/README.md) and [`notebooks/envelope_encryption_v2/`](notebooks/envelope_encryption_v2/README.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).

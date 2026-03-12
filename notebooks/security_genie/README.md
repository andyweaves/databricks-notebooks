# Security Genie

Security Genie is an AI-powered security auditing tool for Databricks. It provides a Genie space that helps platform users analyse user activities and system events for security and monitoring purposes using natural language queries backed by SQL functions and audit log analysis.

## Files

| File | Purpose |
|------|---------|
| `setup.sql` | Creates the catalog/schema, defines SQL table functions for detecting failed authentication and IP access attempts. **Run this first.** |
| `etl.sql` | Creates a materialized view (`audit_logs`) over `system.access.audit` with documented column schemas. **Run this second.** |
| `check_ip_acls_against_system_tables.py` | Fetches workspace IP access lists via the Databricks SDK, combines them with RFC 1918 private ranges, builds a `good_ips_list` table, and defines the `auth_attempts_outside_perimeter()` function for detecting login attempts from untrusted networks. |
| `example_sql_queries.sql` | A collection of ready-to-use SQL queries covering common security questions (failed auth, IP ACL denials, secret access, Delta Sharing denials, Databricks support access, security posture checks). |
| `instructions.txt` | Genie space instructions that guide the AI assistant on how to respond to security-related questions. |
| `metadata.md` | Genie space metadata (description and sample questions). |

## Setup

1. **Configure widget parameters** (see below).
2. **Run `setup.sql`** to create the target schema and the `failed_authentication_attempts()` and `failed_ip_access_attempts()` table functions.
3. **Run `etl.sql`** to create the `audit_logs` materialized view.
4. **Run `check_ip_acls_against_system_tables.py`** to populate the `good_ips_list` table and create the `auth_attempts_outside_perimeter()` function.

## Widget Parameters

The notebooks use Databricks widgets to parameterise the target catalog and schema:

| Widget | Default | Description |
|--------|---------|-------------|
| `catalog` | `main` | The Unity Catalog catalog to use |
| `schema` | `default` | The schema within the catalog |

## Custom Functions

| Function | Detects |
|----------|---------|
| `failed_authentication_attempts()` | Repeated failed login/auth attempts (HTTP 401) that could indicate brute-force attacks. Returns the last 90 days, grouped by user and date. |
| `failed_ip_access_attempts()` | Requests denied by IP access lists (`IpAccessDenied`, `accountIpAclsValidationFailed`), indicating access from untrusted IP ranges. Returns the last 90 days, grouped by source IP and date. |
| `auth_attempts_outside_perimeter()` | Authentication attempts originating from IP addresses outside the configured IP ACLs and private ranges. Useful for detecting login attempts from untrusted networks before IP ACL enforcement. |

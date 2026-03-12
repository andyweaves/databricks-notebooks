# SQL Alert Definitions

This directory contains Databricks SQL alert definitions in JSON format.

## Alerts

### `alerts/serverless_egress_denied_24_hours.dbalert.json`

Monitors the `system.access.outbound_network` table for serverless compute outbound network events that have been denied (DROP or DRY_RUN_DENIAL) within the last 24 hours. The alert runs twice daily (07:00 and 15:00 Europe/London) and triggers when any denied events are found, notifying on both alert and OK states.

# Red Team

Red teaming toolkit for probing AI model endpoints for security weaknesses, built on [BlackIce](https://www.databricks.com/blog/announcing-blackice-containerized-red-teaming-toolkit-ai-security-testing) and [Garak](https://docs.garak.ai/garak).

## What It Does

BlackIce is an open-source containerized toolkit for red teaming AI models. It wraps Garak, which probes LLMs for hallucination, data leakage, prompt injection, misinformation, toxicity generation, jailbreaks, and other weaknesses. Think of Garak as `nmap` or Metasploit, but for LLMs.

The notebook targets a Databricks Model Serving endpoint, runs configurable attack probes against it, and produces a hit log of successful attacks. Results can also be cross-referenced with the inference table to see which attacks were blocked by guardrails versus which got through.

## Files

| File / Directory | Description |
|-----------------|-------------|
| `blackice.py` | Main Databricks notebook for running Garak scans against a serving endpoint |
| `utils/databricks.py` | Helper to create a `WorkspaceClient` and list serving endpoints |
| `utils/garak.py` | Helper to generate Garak REST API configuration files and manage environment variables |
| `alerts/ai_guardrails_triggered_last_24_hours.dbalert.json` | Databricks SQL alert definition that monitors for guardrail-triggered events in inference tables |
| `alerts/serverless_egress_denied_last_24_hours.dbalert.json` | Databricks SQL alert definition that monitors for denied outbound network connections (serverless egress control) |

## Prerequisites

- **DBR 17.3-LTS cluster** running the `databricksruntime/blackice:17.3-LTS` container image via [Databricks Container Services](https://docs.databricks.com/aws/en/compute/custom-containers)
- A deployed Model Serving endpoint to target
- If guardrails are configured on the target endpoint, Garak's `skip_codes` should include `400` (guardrail rejections return 400 BAD REQUEST, which Garak would otherwise treat as a connection failure)

## Alert Definitions

Two Databricks SQL alert JSON definitions are included in `alerts/`:

- **AI Guardrails Triggered**: Queries the inference table for non-200 responses and extracts the guardrail label or detected categories. Fires on a cron schedule (7:00 and 15:00 Europe/London) if any guardrail events are found.
- **Serverless Egress Denied**: Queries `system.access.outbound_network` for DROP or DRY_RUN_DENIAL events. Useful for detecting unauthorized outbound connections from serverless compute.

Both alerts require customization of the catalog/schema/table references before deployment.

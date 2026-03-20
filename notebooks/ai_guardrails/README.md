# AI Guardrails for Databricks

AI guardrails are safety layers that sit between users and LLM endpoints on Databricks. They intercept requests and responses via [AI Gateway](https://www.databricks.com/product/artificial-intelligence/ai-gateway), scanning for harmful content, prompt injection attacks, and insecure generated code before they reach or leave the model.

Each guardrail is packaged as an MLflow pyfunc model, registered in Unity Catalog, and deployed to a Model Serving endpoint. AI Gateway then routes traffic through these endpoints as custom input or output guardrails.

## Directory Structure

| Directory | Purpose |
|-----------|---------|
| `llama_guard/` | Content safety classification using Meta Llama Guard 3 (1B/8B) and Llama Guard 4 (12B). Deployed as **input** guardrails to block harmful prompts across 14 safety categories. |
| `prompt_guard/` | Prompt injection and jailbreak detection using Meta Prompt Guard 2 (22M/86M). Deployed as **input** guardrails to detect malicious prompt manipulation. |
| `code_shield/` | Code vulnerability scanning using Meta Code Shield. Deployed as an **output** guardrail to catch insecure LLM-generated code across 7 programming languages. |
| `llama_firewall/` | Unified guardrail framework using Meta's LlamaFirewall. Deploys PromptGuard + Llama Guard 4 as a combined **input** guardrail and CodeShield as an **output** guardrail through a single policy engine. Consolidates the standalone guardrails above into fewer endpoints. |
| `red_team/` | Red teaming toolkit using BlackIce and Garak to probe deployed models for weaknesses, plus Databricks SQL alert definitions for monitoring guardrail activity. |

## File Naming Convention

Within each guardrail directory, there are two types of Python files:

- **Hyphenated names** (e.g., `llama-guard-3.py`) -- MLflow pyfunc model class definitions. These contain the guardrail logic and are referenced by `set_model()` at the bottom.
- **Underscored names** (e.g., `llama_guard_3.py`) -- Databricks notebook source files that handle the full deployment workflow: downloading the model, logging to MLflow, registering in Unity Catalog, deploying to Model Serving, and testing.

## General Prerequisites

- **GPU compute**: Llama Guard and Prompt Guard models require GPU clusters (serverless or provisioned). Llama Guard 4 specifically requires multi-GPU nodes.
- **HuggingFace access token**: Required to download Meta Llama models. Store as a Databricks secret.
- **Meta Llama access**: You must accept the Meta Llama license agreement on HuggingFace or llama.com before downloading models.
- **AI Gateway**: Must be enabled on your Databricks workspace to attach guardrails to foundation model endpoints.
- **Unity Catalog**: Models are registered in UC for versioning and governance.

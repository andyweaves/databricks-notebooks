# Llama Guard

Content safety guardrails powered by Meta's Llama Guard models. These classify user prompts against 14 safety categories and return accept/reject decisions in Databricks Guardrails format for use as **input** guardrails on AI Gateway.

## Models

| Model | Parameters | Notes |
|-------|-----------|-------|
| [Llama Guard 3 1B](https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Guard3/1B/MODEL_CARD.md) | 1 billion | Lightweight, suitable for serverless high-memory compute (32 GB+) |
| [Llama Guard 3 8B](https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Guard3/8B/MODEL_CARD.md) | 8 billion | Higher accuracy, requires GPU compute |
| [Llama Guard 4 12B](https://huggingface.co/meta-llama/Llama-Guard-4-12B) | 12 billion | Latest generation with vision support, requires multi-GPU (deployed on GPU clusters) |

## Files

| File | Type | Description |
|------|------|-------------|
| `llama-guard-3.py` | Model class | MLflow pyfunc guardrail definition for Llama Guard 3 |
| `llama-guard-4.py` | Model class | MLflow pyfunc guardrail definition for Llama Guard 4 |
| `llama_guard_3.py` | Deployment notebook | End-to-end notebook: download, log, register, deploy, and test Llama Guard 3 |
| `llama_guard_4_gpu.py` | Deployment notebook | End-to-end notebook: download, log, register, deploy, and test Llama Guard 4 (GPU) |

## Safety Categories

All Llama Guard models classify content across these 14 categories:

- **S1**: Violent Crimes
- **S2**: Non-Violent Crimes
- **S3**: Sex-Related Crimes
- **S4**: Child Sexual Exploitation
- **S5**: Defamation
- **S6**: Specialized Advice
- **S7**: Privacy
- **S8**: Intellectual Property
- **S9**: Indiscriminate Weapons
- **S10**: Hate
- **S11**: Suicide & Self-Harm
- **S12**: Sexual Content
- **S13**: Elections
- **S14**: Code Interpreter Abuse

## Compute Requirements

- **Llama Guard 3 1B**: Serverless high-memory compute (32 GB+) or GPU cluster
- **Llama Guard 3 8B**: GPU cluster (Medium workload size recommended)
- **Llama Guard 4 12B**: Multi-GPU cluster with `device_map="auto"` and bfloat16 precision

## Prerequisites

- HuggingFace access token with Meta Llama model access
- Unity Catalog for model registration
- AI Gateway enabled on the workspace

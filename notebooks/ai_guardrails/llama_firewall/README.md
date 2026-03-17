# LlamaFirewall

Unified guardrail framework powered by Meta's [LlamaFirewall](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall) that orchestrates multiple security scanners through a single policy engine. This notebook deploys two endpoints — an **input** guardrail combining PromptGuard + Llama Guard 4, and an **output** guardrail using CodeShield — for use with [AI Gateway](https://www.databricks.com/product/artificial-intelligence/ai-gateway).

## Why LlamaFirewall?

The standalone [Prompt Guard](../prompt_guard/), [Llama Guard](../llama_guard/), and [Code Shield](../code_shield/) guardrails each require their own endpoint. LlamaFirewall consolidates them:

- **Input endpoint**: PromptGuard (jailbreak/injection detection) **and** Llama Guard 4 (content safety) in a single GPU endpoint, rejecting if either scanner flags the input
- **Output endpoint**: CodeShield (insecure code detection) via LlamaFirewall's synchronous API — no async complexity needed

## Architecture

```
User Input -> [PromptGuard + Llama Guard 4 (input)] -> Foundation Model -> [CodeShield (output)] -> Response
```

## What Gets Deployed

| Endpoint | Scanners | Type | Compute |
|----------|----------|------|---------|
| `llama-firewall-input` | PromptGuard + Llama Guard 4 | Input guardrail | GPU_MEDIUM (A10) |
| `llama-firewall-output` | CodeShield | Output guardrail | Small CPU |

## Files

| File | Type | Description |
|------|------|-------------|
| `llama-firewall-input.py` | Model class | MLflow pyfunc combining PromptGuard + Llama Guard 4 for input scanning |
| `llama-firewall-output.py` | Model class | MLflow pyfunc using LlamaFirewall CodeShield for output scanning |
| `llama_firewall.py` | Deployment notebook | End-to-end notebook: configure, download, log, deploy, and test both endpoints |

## Scanners Used

### PromptGuard (Input)
Detects jailbreak attempts and prompt injection attacks. Lightweight binary classifier that flags malicious inputs before they reach the foundation model.

### Llama Guard 4 (Input)
12B parameter safety classifier that detects harmful content across 14 categories:

- **S1**: Violent Crimes, **S2**: Non-Violent Crimes, **S3**: Sex-Related Crimes, **S4**: Child Sexual Exploitation
- **S5**: Defamation, **S6**: Specialized Advice, **S7**: Privacy, **S8**: Intellectual Property
- **S9**: Indiscriminate Weapons, **S10**: Hate, **S11**: Suicide & Self-Harm, **S12**: Sexual Content
- **S13**: Elections, **S14**: Code Interpreter Abuse

### CodeShield (Output)
Static security analysis of LLM-generated code across 7 programming languages. Three outcomes: allow, warn (sanitize), or block (reject).

## Prerequisites

- HuggingFace access token with Meta Llama model access
- [Serverless GPU compute](https://docs.databricks.com/aws/en/compute/serverless/dependencies#use-serverless-gpu-compute) (A10 GPU recommended)
- Unity Catalog for model registration
- AI Gateway enabled on the workspace

## Quick Start

1. Import `llama_firewall.py` into your Databricks workspace
2. Attach to a serverless GPU cluster (A10)
3. Fill in the widgets (catalog, schema, HuggingFace token)
4. Run all cells — the notebook handles everything from download to deployment
5. Add the endpoints as custom guardrails on your AI Gateway endpoint

## References

- [LlamaFirewall GitHub](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall)
- [Llama Guard 4 on Hugging Face](https://huggingface.co/meta-llama/Llama-Guard-4-12B)
- [Llama Protections](https://www.llama.com/llama-protections/)
- [Databricks AI Gateway Guardrails](https://docs.databricks.com/en/ai-gateway/guardrails.html)

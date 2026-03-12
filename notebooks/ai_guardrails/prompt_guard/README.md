# Prompt Guard

Input guardrail that detects prompt injection and jailbreak attempts using Meta's [Prompt Guard 2](https://www.llama.com/llama-protections/) models. It classifies incoming user messages into three categories: SAFE, JAILBREAK, or PROMPT_INJECTION.

## How It Works

Prompt Guard is deployed as an **input** guardrail on AI Gateway. It intercepts user messages before they reach the foundation model and runs them through a sequence classification model. If the message is classified as a jailbreak or prompt injection attempt, the request is rejected with a descriptive error message.

## Model Variants

| Model | Parameters | Description |
|-------|-----------|-------------|
| [Prompt Guard 2 22M](https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Prompt-Guard-2/22M/MODEL_CARD.md) | 22 million | Lightweight variant for low-latency use cases |
| [Prompt Guard 2 86M](https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Prompt-Guard-2/86M/MODEL_CARD.md) | 86 million | Higher accuracy variant |

## Detection Categories

- **SAFE** (class 0): Normal user input, allowed to proceed.
- **JAILBREAK** (class 1): Malicious instructions designed to override the model's safety features.
- **PROMPT_INJECTION** (class 2): Inputs that exploit untrusted third-party data in the context window to execute unintended instructions.

## Files

| File | Type | Description |
|------|------|-------------|
| `llama-prompt-guard-2.py` | Model class | MLflow pyfunc guardrail definition for Prompt Guard 2 |
| `prompt_guard_2.py` | Deployment notebook | End-to-end notebook: download, log, register, deploy, and test Prompt Guard 2 |

## Prerequisites

- HuggingFace access token with Meta Llama model access
- GPU cluster or serverless compute (models are small enough for CPU but benefit from GPU)
- Unity Catalog for model registration
- AI Gateway enabled on the workspace

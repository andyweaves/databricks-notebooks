# Code Shield

Output guardrail that scans LLM-generated code for security vulnerabilities using Meta's [Code Shield](https://www.llama.com/llama-protections/) library. When a model generates code in its response, Code Shield analyzes it and either allows, warns, or blocks the response based on the severity of detected issues.

## How It Works

Code Shield is deployed as an **output** guardrail on AI Gateway. It intercepts model responses, extracts code content from the assistant's message, and runs a static security scan. Based on the scan result:

- **No issues**: The response proceeds to the user unchanged.
- **Warning-level issues**: The response is sanitized with a security warning appended.
- **Block-level issues**: The response is rejected entirely with an insecure code message.

## Supported Languages

Code Shield provides inference-time filtering for **7 programming languages** with an average latency of ~200ms.

## Files

| File | Type | Description |
|------|------|-------------|
| `llama-code-shield.py` | Model class | MLflow pyfunc guardrail definition using the `codeshield` library |
| `code_shield.py` | Deployment notebook | End-to-end notebook: log, register, deploy, and test Code Shield |

## Prerequisites

- `codeshield==1.0.1` (installed automatically via pip requirements)
- `nest-asyncio==1.6.0` (for async compatibility in serving environments)
- No GPU required -- Code Shield runs on CPU (Small workload size)
- Unity Catalog for model registration
- AI Gateway enabled on the workspace

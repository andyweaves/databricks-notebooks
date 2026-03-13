# LlamaFirewall on Databricks

[LlamaFirewall](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall) is Meta's open-source, unified guardrail framework for LLM-powered applications. Released as part of the PurpleLlama project, it orchestrates multiple security scanners through a single policy engine -- providing a **defense-in-depth** approach to AI safety.

## What This Notebook Deploys

A single notebook (`llama_firewall.py`) deploys **two** guardrail endpoints using LlamaFirewall:

| Endpoint | Scanners | Gateway Type | What It Catches |
|----------|---------|-------------|-----------------|
| `llama-firewall-input` | LlamaFirewall PromptGuard + Llama Guard 4 | Input guardrail | Jailbreaks, prompt injections, harmful content (S1-S14) |
| `llama-firewall-output` | LlamaFirewall CodeShield | Output guardrail | Insecure LLM-generated code (50+ CWEs across 8 languages) |

### Why Combine PromptGuard and Llama Guard 4?

| Guardrail | What It Catches | What It Misses |
|-----------|----------------|----------------|
| **PromptGuard** | Jailbreaks, prompt injections | Harmful content that isn't a manipulation attack |
| **Llama Guard 4** | Harmful content across 14 safety categories (S1-S14) | Subtle prompt injection techniques |
| **Combined** | Both manipulation attacks AND harmful content | Significantly reduced blind spots |

## Files

| File | Purpose |
|------|---------|
| `llama_firewall.py` | Deployment notebook -- configures LlamaFirewall, downloads Llama Guard 4, logs/tests/deploys both endpoints |
| `llama-firewall-input.py` | Model class for input guardrail (PromptGuard + Llama Guard 4) |
| `llama-firewall-output.py` | Model class for output guardrail (CodeShield) |

## LlamaFirewall Scanners Used

### PromptGuard (Input)
- **Purpose**: Detects jailbreak and prompt injection attacks
- **Model**: DeBERTa-based classifier (22M or 86M parameters)
- **Performance**: 97.5% detection rate at 1% false positive rate

### Llama Guard 4 (Input)
- **Purpose**: Classifies content across 14 safety categories (S1-S14)
- **Model**: Llama 4 12B parameter model
- **Note**: Not a built-in LlamaFirewall scanner; runs alongside LlamaFirewall in a unified pyfunc

### CodeShield (Output)
- **Purpose**: Detects insecure LLM-generated code via static analysis
- **Engine**: Semgrep + regex rules across 8 programming languages
- **Coverage**: 50+ CWEs
- **Compute**: CPU-based (Small workload)

## Comparison with Standalone Guardrails

| Capability | Standalone Approach | LlamaFirewall Approach |
|------------|-------------------|----------------------|
| **Prompt Injection Detection** | Deploy Prompt Guard 2 separately (`../prompt_guard/`) | `ScannerType.PROMPT_GUARD` -- same model, unified config |
| **Code Vulnerability Scanning** | Deploy Code Shield separately (`../code_shield/`) | `ScannerType.CODE_SHIELD` -- same engine, unified config |
| **Content Safety** | Deploy Llama Guard 4 separately (`../llama_guard/`) | Llama Guard 4 alongside LlamaFirewall in a unified pyfunc |
| **Installation** | Multiple packages + manual HF downloads | `pip install llamafirewall` |
| **Configuration** | Custom Python class per guardrail | Declarative scanner assignment per role |

## Prerequisites

- **Databricks Runtime**: 15.4 LTS ML or later
- **AI Gateway**: Must be enabled on your workspace
- **Unity Catalog**: For model registration and governance
- **GPU compute**: [Serverless GPU compute](https://docs.databricks.com/aws/en/compute/serverless/dependencies#use-serverless-gpu-compute) (A10 GPU sufficient)
- **Model Serving**: [GPU_MEDIUM endpoint](https://docs.databricks.com/aws/en/machine-learning/model-serving/custom-models#compute-type) for input guardrail; Small CPU endpoint for output guardrail
- **HuggingFace access**: Required for Llama Guard 4 download
- **Meta Llama 4 access**: Request access [here](https://www.llama.com/llama-downloads/) or via HuggingFace

## Architecture

```
User Input → [PromptGuard + Llama Guard 4 (input)] → Foundation Model → [CodeShield (output)] → Response
              (jailbreaks + harmful content)                              (insecure code)
```

## Quick Start

```python
# Install
%pip install llamafirewall

# Configure (downloads required models)
!llamafirewall configure

# Use
from llamafirewall import LlamaFirewall, UserMessage, AssistantMessage, Role, ScannerType

firewall = LlamaFirewall(
    scanners={
        Role.USER: [ScannerType.PROMPT_GUARD],
        Role.ASSISTANT: [ScannerType.CODE_SHIELD],
    }
)

result = firewall.scan(UserMessage(content="Hello, how are you?"))
print(result.action)  # Action.ALLOW
```

## References

- [LlamaFirewall Documentation](https://meta-llama.github.io/PurpleLlama/LlamaFirewall/)
- [LlamaFirewall Architecture](https://meta-llama.github.io/PurpleLlama/LlamaFirewall/docs/documentation/llamafirewall-architecture/architecture)
- [LlamaFirewall on PyPI](https://pypi.org/project/llamafirewall/)
- [Research Paper (arXiv:2505.03574)](https://arxiv.org/abs/2505.03574)

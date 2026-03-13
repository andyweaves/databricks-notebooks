# LlamaFirewall on Databricks

[LlamaFirewall](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall) is Meta's open-source, unified guardrail framework for LLM-powered applications. Released as part of the PurpleLlama project, it orchestrates multiple security scanners through a single policy engine -- providing a **defense-in-depth** approach to AI safety.

## Why LlamaFirewall?

The other guardrails in this repo (`llama_guard/`, `prompt_guard/`, `code_shield/`) each address a single concern and are deployed independently. LlamaFirewall unifies them under one framework and adds a critical new capability: **AlignmentCheck** for auditing agentic AI behavior.

## Comparison with Standalone Guardrails

| Capability | Standalone Approach | LlamaFirewall Approach |
|------------|-------------------|----------------------|
| **Prompt Injection Detection** | Deploy Prompt Guard 2 separately (`../prompt_guard/`) | `ScannerType.PROMPT_GUARD` -- same model, unified config |
| **Code Vulnerability Scanning** | Deploy Code Shield separately (`../code_shield/`) | `ScannerType.CODE_SHIELD` -- same engine, unified config |
| **Content Safety** | Deploy Llama Guard 3/4 separately (`../llama_guard/`) | Not yet in LlamaFirewall (use standalone) |
| **Agent Chain-of-Thought Auditing** | **Not available** | `ScannerType.AGENT_ALIGNMENT` -- **unique to LlamaFirewall** |
| **Installation** | Multiple packages + manual HF downloads | `pip install llamafirewall` |
| **Configuration** | Custom Python class per guardrail | Declarative scanner assignment per role |

## Notebooks

### Model Class Definitions (hyphenated names)

| File | Scanner | Gateway Type | Comparable To |
|------|---------|-------------|---------------|
| `llama-firewall-input.py` | PromptGuard | Input guardrail | `../prompt_guard/llama-prompt-guard-2.py` |
| `llama-firewall-output.py` | CodeShield | Output guardrail | `../code_shield/llama-code-shield.py` |
| `llama-firewall-alignment.py` | AlignmentCheck | Input guardrail | **No equivalent** |

### Deployment Notebooks (underscored names)

| File | Purpose | Comparable To |
|------|---------|---------------|
| `llama_firewall_input.py` | Deploy PromptGuard via LlamaFirewall | `../prompt_guard/prompt_guard_2.py` |
| `llama_firewall_output.py` | Deploy CodeShield via LlamaFirewall | `../code_shield/code_shield.py` |
| `llama_firewall_alignment.py` | Deploy AlignmentCheck (agent auditing) | **No equivalent** |

## LlamaFirewall Scanners

### PromptGuard
- **Purpose**: Detects jailbreak and prompt injection attacks
- **Model**: DeBERTa-based classifier (22M or 86M parameters)
- **Performance**: 97.5% detection rate at 1% false positive rate
- **Compute**: CPU or GPU (Small workload)

### CodeShield
- **Purpose**: Detects insecure LLM-generated code via static analysis
- **Engine**: Semgrep + regex rules across 8 programming languages
- **Coverage**: 50+ CWEs
- **Compute**: CPU-based (Small workload)

### AlignmentCheck
- **Purpose**: Audits agent chain-of-thought reasoning in real time
- **Model**: Few-shot prompting via Llama 4 Maverick
- **Detects**: Indirect prompt injection, goal hijacking, agent misalignment
- **Performance**: 83% detection rate at 2.5% false positive rate
- **Compute**: GPU recommended (Medium workload)

## Prerequisites

- **Databricks Runtime**: 15.4 LTS ML or later
- **AI Gateway**: Must be enabled on your workspace
- **Unity Catalog**: For model registration and governance
- **GPU compute**: Required for AlignmentCheck, recommended for PromptGuard
- **HuggingFace access**: Required for initial model downloads

## Recommended Architecture

For comprehensive agent security, deploy all three scanners:

```
User Input → [PromptGuard] → Agent LLM → [AlignmentCheck] → [CodeShield] → Response
               (input)                       (input)           (output)
```

## Quick Start

```python
# Install
%pip install llamafirewall

# Configure (downloads required models)
!llamafirewall configure

# Use
from llamafirewall import LlamaFirewall, UserMessage, Role, ScannerType

firewall = LlamaFirewall(
    scanners={
        Role.USER: [ScannerType.PROMPT_GUARD],
        Role.ASSISTANT: [ScannerType.AGENT_ALIGNMENT, ScannerType.CODE_SHIELD],
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


"""
Custom Output Guardrail using LlamaFirewall (CodeShield scanner).

LlamaFirewall is Meta's unified guardrail framework that orchestrates multiple
security scanners. This model class uses the CodeShield scanner to detect
insecure LLM-generated code.

Compared to deploying Code Shield standalone:
- LlamaFirewall wraps CodeShield with a unified policy engine
- Same underlying Semgrep + regex-based static analysis
- Covers 50+ CWEs across 8 programming languages
- Declarative configuration via scanner assignments

This guardrail:
1. Translates OpenAI Chat Completions output format to extract code content
2. Uses LlamaFirewall's CodeShield scanner to detect insecure code
3. Translates the response back to Databricks Guardrails format
"""
from typing import Any, Dict, List
import mlflow
from mlflow.models import set_model
import pandas as pd
import os

class LlamaFirewallOutputModel(mlflow.pyfunc.PythonModel):
    def __init__(self):
        self.firewall = None

    def load_context(self, context):
        """Initialize LlamaFirewall with CodeShield scanner for assistant outputs."""
        from llamafirewall import LlamaFirewall, Role, ScannerType

        self.firewall = LlamaFirewall(
            scanners={
                Role.ASSISTANT: [ScannerType.CODE_SHIELD],
            }
        )

    def _invoke_guardrail(self, code_content: str) -> Dict[str, Any]:
        """
        Invokes LlamaFirewall's CodeShield scanner to detect insecure code.

        Returns:
            Dict with scan results
        """
        from llamafirewall import AssistantMessage

        result = self.firewall.scan(AssistantMessage(content=code_content))

        flagged = result.action.value != "allow"

        return {
            "is_insecure": flagged,
            "action": result.action.value,
            "reason": result.reason if result.reason else None,
            "scanner": "CodeShield"
        }

    def _translate_output_guardrail_request(self, request: dict) -> str:
        """
        Translates an OpenAI Chat Completions (ChatV1) response to extract code content.
        """
        if (request["mode"]["phase"] != "output") or (request["mode"]["stream_mode"] is None) or (request["mode"]["stream_mode"] == "streaming"):
            raise Exception(f"Invalid mode: {request}.")
        if ("choices" not in request):
            raise Exception(f"Missing key \"choices\" in request: {request}.")

        choices = request["choices"]
        code_content = ""

        for choice in choices:
            if ("message" not in choice):
                raise Exception(f"Missing key \"message\" in \"choices\": {request}.")
            if ("content" not in choice["message"]):
                raise Exception(f"Missing key \"content\" in \"choices[\"message\"]\": {request}.")
            code_content += choice["message"]["content"]

        return code_content

    def _translate_guardrail_response(self, scan_result: Dict[str, Any], original_content: str) -> Dict[str, Any]:
        """
        Translates LlamaFirewall CodeShield scan results to the Databricks Guardrails format.
        """
        if scan_result["is_insecure"]:
            if scan_result["action"] == "block":
                return {
                    "decision": "reject",
                    "reject_message": (
                        f"🚫🚫🚫 The generated code has been flagged as insecure by LlamaFirewall (CodeShield). 🚫🚫🚫\n"
                        f"Reason: {scan_result['reason']}"
                    )
                }
            else:
                warning_message = "⚠️⚠️⚠️ WARNING: The generated code has been flagged as having potential security issues by LlamaFirewall (CodeShield). Please review carefully before use. ⚠️⚠️⚠️"
                return {
                    "decision": "sanitize",
                    "guardrail_response": {"include_in_response": True, "response": warning_message, "scan_result": scan_result},
                    "sanitized_input": {
                        "choices": [{
                            "message": {
                                "role": "assistant",
                                "content": original_content
                            }
                        }]
                    }
                }

        return {
            "decision": "proceed",
            "guardrail_response": {"include_in_response": True, "response": scan_result}
        }

    def predict(self, context, model_input, params=None):
        """
        Applies the Code Shield guardrail to the model output and returns the guardrail response.
        """
        if isinstance(model_input, pd.DataFrame):
            model_input = model_input.to_dict("records")
            model_input = model_input[0]
            if not isinstance(model_input, dict):
                return {"decision": "reject", "reject_reason": f"Couldn't parse model input: {model_input}"}
        elif not isinstance(model_input, dict):
            return {"decision": "reject", "reject_reason": f"Couldn't parse model input: {model_input}"}

        try:
            code_content = self._translate_output_guardrail_request(model_input)
            scan_result = self._invoke_guardrail(code_content)
            result = self._translate_guardrail_response(scan_result, code_content)
            return result
        except Exception as e:
            error_message = str(e)
            return {"decision": "reject", "reject_reason": f"Errored with the following error message: {error_message}"}

set_model(LlamaFirewallOutputModel())

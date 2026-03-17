"""
Custom Guardrail using LlamaFirewall with CodeShield.

This guardrail uses LlamaFirewall's CodeShield scanner to detect security
vulnerabilities in LLM-generated code. It works as an output guardrail,
scanning model responses before they reach the user.

Three outcomes:
- reject: Block-level issues found, response is blocked entirely
- sanitize: Warning-level issues found, response includes a security warning
- proceed: No security issues detected
"""
from typing import Any, Dict
import mlflow
from mlflow.models import set_model
import pandas as pd


class LlamaFirewallOutputModel(mlflow.pyfunc.PythonModel):
    def __init__(self):
        self.firewall = None

    def load_context(self, context):
        """Initialize LlamaFirewall with CodeShield scanner."""
        from llamafirewall import LlamaFirewall, ScannerType, Role

        self.firewall = LlamaFirewall(
            scanners={Role.ASSISTANT: [ScannerType.CODE_SHIELD]}
        )

    def _invoke_guardrail(self, code_content: str) -> Dict[str, Any]:
        """
        Scan code using LlamaFirewall CodeShield.

        Returns:
            Dict with 'flagged' (bool), 'action' (str), and 'reason' (str) keys
        """
        from llamafirewall import AssistantMessage

        result = self.firewall.scan(AssistantMessage(content=code_content))

        action = result.decision.value
        flagged = action != "allow"

        return {
            "flagged": flagged,
            "action": action,
            "reason": str(result.reason) if result.reason else None,
            "raw_output": str(result)
        }

    def _translate_output_guardrail_request(self, request: Dict[str, Any]) -> str:
        """
        Translates an OpenAI Chat Completions (ChatV1) response to extract code content.
        """
        if (request["mode"]["phase"] != "output") or (request["mode"]["stream_mode"] is None) or (request["mode"]["stream_mode"] == "streaming"):
            raise Exception(f"Invalid mode: {request}.")
        if "choices" not in request:
            raise Exception(f"Missing key \"choices\" in request: {request}.")

        choices = request["choices"]
        code_content = ""

        for choice in choices:
            if "message" not in choice:
                raise Exception(f"Missing key \"message\" in \"choices\": {request}.")
            if "content" not in choice["message"]:
                raise Exception(f"Missing key \"content\" in \"choices[\"message\"]\": {request}.")

            code_content += choice["message"]["content"]

        return code_content

    def _translate_guardrail_response(self, scan_result: Dict[str, Any], original_content: str) -> Dict[str, Any]:
        """
        Translates LlamaFirewall CodeShield scan results to Databricks Guardrails format.
        """
        if scan_result["flagged"]:
            if scan_result["action"] == "block":
                return {
                    "decision": "reject",
                    "reject_message": (
                        f"The generated code has been flagged as insecure by AI guardrails. "
                        f"Reason: {scan_result['reason']}"
                    )
                }
            else:
                # warn or other non-allow actions — sanitize
                warning_message = (
                    "WARNING: The generated code has been flagged as having potential "
                    "security issues by AI guardrails. Please review carefully before use."
                )
                return {
                    "decision": "sanitize",
                    "guardrail_response": {
                        "include_in_response": True,
                        "response": warning_message,
                        "scan_result": scan_result
                    },
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
            "guardrail_response": {
                "include_in_response": True,
                "response": scan_result
            }
        }

    def predict(self, context, model_input, params=None):
        """Applies the CodeShield guardrail to model output and returns a guardrail response."""
        if isinstance(model_input, pd.DataFrame):
            model_input = model_input.to_dict("records")
            model_input = model_input[0]
            if not isinstance(model_input, dict):
                return {"decision": "reject", "reject_message": f"Could not parse model input: {model_input}"}
        elif not isinstance(model_input, dict):
            return {"decision": "reject", "reject_message": f"Could not parse model input: {model_input}"}

        try:
            code_content = self._translate_output_guardrail_request(model_input)
            scan_result = self._invoke_guardrail(code_content)
            result = self._translate_guardrail_response(scan_result, code_content)
            return result
        except Exception as e:
            error_message = str(e)
            return {"decision": "reject", "reject_message": f"Failed with an exception: {error_message}"}

set_model(LlamaFirewallOutputModel())

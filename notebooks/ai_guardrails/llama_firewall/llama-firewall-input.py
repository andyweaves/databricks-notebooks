
"""
Custom Input Guardrail using LlamaFirewall (PromptGuard scanner).

LlamaFirewall is Meta's unified guardrail framework that orchestrates multiple
security scanners. This model class uses the PromptGuard scanner to detect
jailbreak and prompt injection attacks.

Compared to deploying Prompt Guard 2 standalone:
- LlamaFirewall wraps PromptGuard with a unified policy engine
- Configuration is declarative (scanner assignments per role)
- Easily extensible to add AlignmentCheck or custom scanners
- Same underlying PromptGuard 2 model for detection

This guardrail:
1. Translates OpenAI Chat Completions format to LlamaFirewall format
2. Uses LlamaFirewall's PromptGuard scanner to detect jailbreaks and injections
3. Translates the response back to Databricks Guardrails format
"""
from typing import Any, Dict, List
import mlflow
from mlflow.models import set_model
import pandas as pd
import os

class LlamaFirewallInputModel(mlflow.pyfunc.PythonModel):
    def __init__(self):
        self.firewall = None

    def load_context(self, context):
        """Initialize LlamaFirewall with PromptGuard scanner for user inputs."""
        from llamafirewall import LlamaFirewall, Role, ScannerType

        self.firewall = LlamaFirewall(
            scanners={
                Role.USER: [ScannerType.PROMPT_GUARD],
            }
        )

    def _invoke_guardrail(self, input_text: str) -> Dict[str, Any]:
        """
        Invokes LlamaFirewall's PromptGuard scanner to detect jailbreaks and prompt injections.

        Returns:
            Dict with 'flagged' (bool), 'label' (str), and 'score' (float) keys
        """
        from llamafirewall import UserMessage

        result = self.firewall.scan(UserMessage(content=input_text))

        flagged = result.action.value != "allow"
        label = result.reason if result.reason else ("UNSAFE" if flagged else "SAFE")
        score = result.score if hasattr(result, "score") and result.score is not None else (1.0 if flagged else 0.0)

        return {
            "flagged": flagged,
            "label": label,
            "score": score,
            "scanner": "PromptGuard",
            "raw_action": result.action.value
        }

    def _translate_input_guardrail_request(self, request: Dict[str, Any]) -> str:
        """
        Translates an OpenAI Chat Completions (ChatV1) request to text for the guardrail.
        """
        if (request["mode"]["phase"] != "input") or (request["mode"]["stream_mode"] is None):
            raise Exception(f"Invalid mode: {request}.")
        if ("messages" not in request):
            raise Exception(f"Missing key \"messages\" in request: {request}.")

        messages = request["messages"]
        combined_text = []

        for message in messages:
            if ("content" not in message):
                raise Exception(f"Missing key \"content\" in \"messages\": {request}.")

            content = message["content"]
            if isinstance(content, str):
                combined_text.append(content)
            elif isinstance(content, list):
                for item in content:
                    if item.get("type") == "text":
                        combined_text.append(item["text"])
            else:
                raise Exception(f"Invalid value type for \"content\": {request}")

        return " ".join(combined_text)

    def _translate_guardrail_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translates the LlamaFirewall response to Databricks Guardrails format.
        """
        if response["flagged"]:
            label = response["label"]
            reject_message = (
                f"🚫🚫🚫 Your request has been flagged by LlamaFirewall ({response['scanner']}): "
                f"{label} (score: {response['score']:.3f}) 🚫🚫🚫"
            )
            return {
                "decision": "reject",
                "reject_message": reject_message,
                "guardrail_response": {"include_in_response": True, "response": response}
            }
        else:
            return {
                "decision": "proceed",
                "guardrail_response": {"include_in_response": True, "response": response}
            }

    def predict(self, context, model_input, params=None):
        """
        Applies the guardrail to the model input and returns a guardrail response.
        """
        # Convert DataFrame to dict if needed
        if isinstance(model_input, pd.DataFrame):
            model_input = model_input.to_dict("records")
            model_input = model_input[0]
            if not isinstance(model_input, dict):
                return {"decision": "reject", "reject_message": f"Could not parse model input: {model_input}"}
        elif not isinstance(model_input, dict):
            return {"decision": "reject", "reject_message": f"Could not parse model input: {model_input}"}

        try:
            # Translate input
            input_text = self._translate_input_guardrail_request(model_input)

            # Invoke guardrail
            guardrail_response = self._invoke_guardrail(input_text)

            # Translate response
            result = self._translate_guardrail_response(guardrail_response)
            return result
        except Exception as e:
            return {"decision": "reject", "reject_message": f"Failed with an exception: {e}"}

set_model(LlamaFirewallInputModel())

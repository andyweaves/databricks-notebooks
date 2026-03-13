
"""
Custom Input Guardrail using LlamaFirewall (AlignmentCheck scanner).

AlignmentCheck is a unique capability of LlamaFirewall with no equivalent in
the standalone Llama Guard, Prompt Guard, or Code Shield tools. It is the
first open-source guardrail to audit LLM chain-of-thought reasoning in real time.

What AlignmentCheck does:
- Analyzes the full conversation trace (user messages + assistant reasoning + tool calls)
- Detects indirect prompt injection via tool responses
- Catches goal hijacking where an agent drifts from the user's stated objective
- Identifies agent misalignment between stated reasoning and actual actions

This guardrail:
1. Accepts a full conversation trace in OpenAI Chat Completions format
2. Uses LlamaFirewall's AlignmentCheck scanner to audit the agent's reasoning
3. Returns a Databricks Guardrails formatted response
"""
from typing import Any, Dict, List
import mlflow
from mlflow.models import set_model
import pandas as pd
import os

class LlamaFirewallAlignmentModel(mlflow.pyfunc.PythonModel):
    def __init__(self):
        self.firewall = None

    def load_context(self, context):
        """Initialize LlamaFirewall with AlignmentCheck scanner for assistant traces."""
        from llamafirewall import LlamaFirewall, Role, ScannerType

        self.firewall = LlamaFirewall(
            scanners={
                Role.ASSISTANT: [ScannerType.AGENT_ALIGNMENT],
            }
        )

    def _invoke_guardrail(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Invokes LlamaFirewall's AlignmentCheck scanner to audit agent reasoning.

        Args:
            messages: Conversation trace as list of message dicts

        Returns:
            Dict with alignment check results
        """
        from llamafirewall import UserMessage, AssistantMessage, ToolMessage

        # Convert messages to LlamaFirewall message objects
        trace = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "user":
                trace.append(UserMessage(content=content))
            elif role == "assistant":
                trace.append(AssistantMessage(content=content))
            elif role == "tool":
                trace.append(ToolMessage(content=content))

        # scan_replay analyzes the full conversation trace
        result = self.firewall.scan_replay(trace)

        flagged = result.action.value != "allow"

        return {
            "flagged": flagged,
            "action": result.action.value,
            "reason": result.reason if result.reason else ("MISALIGNED" if flagged else "ALIGNED"),
            "scanner": "AlignmentCheck",
            "score": result.score if hasattr(result, "score") and result.score is not None else (1.0 if flagged else 0.0)
        }

    def _translate_input_guardrail_request(self, request: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Translates an OpenAI Chat Completions (ChatV1) request to a message trace.
        """
        if (request["mode"]["phase"] != "input") or (request["mode"]["stream_mode"] is None):
            raise Exception(f"Invalid mode: {request}.")
        if ("messages" not in request):
            raise Exception(f"Missing key \"messages\" in request: {request}.")

        messages = request["messages"]
        formatted_messages = []

        for message in messages:
            if ("content" not in message):
                raise Exception(f"Missing key \"content\" in \"messages\": {request}.")

            content = message["content"]
            role = message.get("role", "user")

            if isinstance(content, str):
                formatted_messages.append({"role": role, "content": content})
            elif isinstance(content, list):
                text_parts = []
                for item in content:
                    if item.get("type") == "text":
                        text_parts.append(item["text"])
                if text_parts:
                    formatted_messages.append({
                        "role": role,
                        "content": " ".join(text_parts)
                    })
            else:
                raise Exception(f"Invalid value type for \"content\": {request}")

        return formatted_messages

    def _translate_guardrail_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translates the LlamaFirewall AlignmentCheck response to Databricks Guardrails format.
        """
        if response["flagged"]:
            reject_message = (
                f"🚫🚫🚫 Agent behavior flagged by LlamaFirewall (AlignmentCheck): "
                f"{response['reason']} (score: {response['score']:.3f}) 🚫🚫🚫"
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
        Applies the AlignmentCheck guardrail to the conversation trace.
        """
        if isinstance(model_input, pd.DataFrame):
            model_input = model_input.to_dict("records")
            model_input = model_input[0]
            if not isinstance(model_input, dict):
                return {"decision": "reject", "reject_message": f"Could not parse model input: {model_input}"}
        elif not isinstance(model_input, dict):
            return {"decision": "reject", "reject_message": f"Could not parse model input: {model_input}"}

        try:
            messages = self._translate_input_guardrail_request(model_input)
            guardrail_response = self._invoke_guardrail(messages)
            result = self._translate_guardrail_response(guardrail_response)
            return result
        except Exception as e:
            return {"decision": "reject", "reject_message": f"Failed with an exception: {e}"}

set_model(LlamaFirewallAlignmentModel())

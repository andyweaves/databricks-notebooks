
"""
Custom Input Guardrail combining LlamaFirewall (PromptGuard) with Llama Guard 4 content safety.

This model class runs both guardrails in a single endpoint:
- LlamaFirewall PromptGuard: Detects jailbreaks and prompt injections
- Llama Guard 4: Classifies content across 14 safety categories (S1-S14)

Why combine them?
- PromptGuard catches prompt manipulation attacks (jailbreaks, injections)
- Llama Guard 4 catches harmful content categories (violence, hate, etc.)
- Together they provide defense-in-depth from a single Model Serving endpoint

Llama Guard 4 is not a built-in LlamaFirewall scanner, so this notebook demonstrates
how to run it alongside LlamaFirewall in a unified MLflow pyfunc deployment.

This guardrail:
1. Translates OpenAI Chat Completions format to both guardrail formats
2. Runs LlamaFirewall PromptGuard AND Llama Guard 4 in sequence
3. Rejects if EITHER guardrail flags the input
4. Returns combined results in Databricks Guardrails format
"""
from typing import Any, Dict, List
import mlflow
from mlflow.models import set_model
import pandas as pd
import os
import re

class LlamaFirewallWithLlamaGuard4Model(mlflow.pyfunc.PythonModel):
    def __init__(self):
        self.firewall = None
        self.lg4_config = None
        self.lg4_model = None
        self.lg4_processor = None
        self.device = None
        self.unsafe_categories = """S1: Violent Crimes
S2: Non-Violent Crimes
S3: Sex-Related Crimes
S4: Child Sexual Exploitation
S5: Defamation
S6: Specialized Advice
S7: Privacy
S8: Intellectual Property
S9: Indiscriminate Weapons
S10: Hate
S11: Suicide & Self-Harm
S12: Sexual Content
S13: Elections
S14: Code Interpreter Abuse"""

    def load_context(self, context):
        """Load both LlamaFirewall and Llama Guard 4 model."""
        from llamafirewall import LlamaFirewall, Role, ScannerType
        from transformers import AutoConfig, AutoProcessor, Llama4ForConditionalGeneration
        import torch

        # Initialize LlamaFirewall with PromptGuard
        self.firewall = LlamaFirewall(
            scanners={
                Role.USER: [ScannerType.PROMPT_GUARD],
            }
        )

        # Load Llama Guard 4 from artifacts
        model_path = context.artifacts["model_files"]

        self.lg4_config = AutoConfig.from_pretrained(model_path)
        self.lg4_config.text_config.attention_chunk_size = 4096

        self.lg4_processor = AutoProcessor.from_pretrained(model_path)
        self.lg4_model = Llama4ForConditionalGeneration.from_pretrained(
            model_path,
            device_map="auto",
            dtype=torch.bfloat16,
            config=self.lg4_config
        )
        self.lg4_model.eval()

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    def parse_category(self, reason: str) -> str:
        """Parse safety category code to human-readable text."""
        if reason is None:
            return "Unknown"
        for item in self.unsafe_categories.split("\n"):
            if reason in item:
                stripped = item.strip()
                category = stripped.split(": ", 1)[1]
                category = category.split(".")[0]
                return category
        return "Unknown"

    def _invoke_prompt_guard(self, input_text: str) -> Dict[str, Any]:
        """Run LlamaFirewall PromptGuard scanner."""
        from llamafirewall import UserMessage

        result = self.firewall.scan(UserMessage(content=input_text))
        flagged = result.action.value != "allow"
        label = result.reason if result.reason else ("UNSAFE" if flagged else "SAFE")
        score = result.score if hasattr(result, "score") and result.score is not None else (1.0 if flagged else 0.0)

        return {
            "flagged": flagged,
            "label": label,
            "score": score,
            "scanner": "LlamaFirewall/PromptGuard"
        }

    def _invoke_llama_guard_4(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """Run Llama Guard 4 content safety classifier."""
        import torch

        # Format messages for Llama Guard 4
        formatted_messages = []
        for msg in messages:
            formatted_messages.append({
                "role": msg["role"],
                "content": [{"type": "text", "text": msg["content"]}]
            })

        inputs = self.lg4_processor.apply_chat_template(
            formatted_messages,
            add_generation_prompt=True,
            tokenize=True,
            return_dict=True,
            return_tensors="pt",
        ).to(self.device)

        with torch.no_grad():
            outputs = self.lg4_model.generate(
                **inputs,
                do_sample=False,
                max_new_tokens=100
            )

        result = self.lg4_processor.batch_decode(
            outputs[:, inputs["input_ids"].shape[-1]:]
        )[0].strip()

        result = result.replace("<|eot_id|>", "").replace("<|eot|>", "").strip()

        flagged = result.lower().startswith("unsafe")
        categories = []
        category_names = []

        if flagged:
            lines = result.split("\n")
            for line in lines[1:]:
                line = line.strip()
                parts = [p.strip() for p in line.split(",")]
                for part in parts:
                    if part and part.startswith("S"):
                        cat_code = part.split(".")[0].strip()
                        cat_code = cat_code.replace("<|eot_id|>", "").replace("<|eot|>", "").strip()
                        if cat_code not in categories:
                            categories.append(cat_code)
                            category_names.append(self.parse_category(cat_code))

        return {
            "flagged": flagged,
            "label": "UNSAFE" if flagged else "SAFE",
            "categories": categories,
            "category_names": category_names,
            "scanner": "LlamaGuard4",
            "raw_output": result
        }

    def _translate_input_guardrail_request(self, request: Dict[str, Any]) -> tuple:
        """
        Translates an OpenAI Chat Completions request.
        Returns (combined_text, messages_list) for both guardrails.
        """
        if (request["mode"]["phase"] != "input") or (request["mode"]["stream_mode"] is None):
            raise Exception(f"Invalid mode: {request}.")
        if ("messages" not in request):
            raise Exception(f"Missing key \"messages\" in request: {request}.")

        messages = request["messages"]
        combined_text = []
        formatted_messages = []

        for message in messages:
            if ("content" not in message):
                raise Exception(f"Missing key \"content\" in \"messages\": {request}.")

            content = message["content"]
            role = message.get("role", "user")

            if isinstance(content, str):
                combined_text.append(content)
                formatted_messages.append({"role": role, "content": content})
            elif isinstance(content, list):
                text_parts = []
                for item in content:
                    if item.get("type") == "text":
                        text_parts.append(item["text"])
                if text_parts:
                    joined = " ".join(text_parts)
                    combined_text.append(joined)
                    formatted_messages.append({"role": role, "content": joined})
            else:
                raise Exception(f"Invalid value type for \"content\": {request}")

        return " ".join(combined_text), formatted_messages

    def _translate_guardrail_response(self, pg_result: Dict[str, Any], lg4_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translates combined guardrail results to Databricks Guardrails format.
        Rejects if EITHER guardrail flags the input.
        """
        combined_response = {
            "prompt_guard": pg_result,
            "llama_guard_4": lg4_result
        }

        if pg_result["flagged"] and lg4_result["flagged"]:
            categories_str = ", ".join(lg4_result["category_names"]) if lg4_result["category_names"] else "Unknown"
            category_codes = ", ".join(lg4_result["categories"]) if lg4_result["categories"] else "Unknown"
            reject_message = (
                f"🚫🚫🚫 Your request has been flagged by multiple guardrails. 🚫🚫🚫 "
                f"PromptGuard: {pg_result['label']} | "
                f"Llama Guard 4: {categories_str} ({category_codes})"
            )
            return {
                "decision": "reject",
                "reject_message": reject_message,
                "guardrail_response": {"include_in_response": True, "response": combined_response}
            }
        elif pg_result["flagged"]:
            reject_message = (
                f"🚫🚫🚫 Your request has been flagged by LlamaFirewall (PromptGuard): "
                f"{pg_result['label']} (score: {pg_result['score']:.3f}) 🚫🚫🚫"
            )
            return {
                "decision": "reject",
                "reject_message": reject_message,
                "guardrail_response": {"include_in_response": True, "response": combined_response}
            }
        elif lg4_result["flagged"]:
            categories_str = ", ".join(lg4_result["category_names"]) if lg4_result["category_names"] else "Unknown"
            category_codes = ", ".join(lg4_result["categories"]) if lg4_result["categories"] else "Unknown"
            reject_message = (
                f"🚫🚫🚫 Your request has been flagged by Llama Guard 4 as potentially harmful. 🚫🚫🚫 "
                f"Detected categories: {categories_str} ({category_codes})"
            )
            return {
                "decision": "reject",
                "reject_message": reject_message,
                "guardrail_response": {"include_in_response": True, "response": combined_response}
            }
        else:
            return {
                "decision": "proceed",
                "guardrail_response": {"include_in_response": True, "response": combined_response}
            }

    def predict(self, context, model_input, params=None):
        """
        Applies both guardrails and returns a combined response.
        """
        if isinstance(model_input, pd.DataFrame):
            model_input = model_input.to_dict("records")
            model_input = model_input[0]
            if not isinstance(model_input, dict):
                return {"decision": "reject", "reject_message": f"Could not parse model input: {model_input}"}
        elif not isinstance(model_input, dict):
            return {"decision": "reject", "reject_message": f"Could not parse model input: {model_input}"}

        try:
            combined_text, messages = self._translate_input_guardrail_request(model_input)

            # Run both guardrails
            pg_result = self._invoke_prompt_guard(combined_text)
            lg4_result = self._invoke_llama_guard_4(messages)

            result = self._translate_guardrail_response(pg_result, lg4_result)
            return result
        except Exception as e:
            return {"decision": "reject", "reject_message": f"Failed with an exception: {e}"}

set_model(LlamaFirewallWithLlamaGuard4Model())

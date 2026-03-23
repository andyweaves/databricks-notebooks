"""
Custom Guardrail using LlamaFirewall with PromptGuard and Llama Guard 4.

This guardrail combines two scanners in a single input endpoint:
1. LlamaFirewall PromptGuard — detects jailbreaks and prompt injections
2. Llama Guard 4 — detects harmful content across 14 safety categories (S1-S14)

The request is rejected if EITHER scanner flags the input.
"""
from typing import Any, Dict, List
import mlflow
from mlflow.models import set_model
import pandas as pd
import os


class LlamaFirewallInputModel(mlflow.pyfunc.PythonModel):
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
        """Load LlamaFirewall (PromptGuard) and Llama Guard 4 model."""
        from llamafirewall import LlamaFirewall, ScannerType, Role
        from transformers import AutoConfig, AutoProcessor, Llama4ForConditionalGeneration
        import torch

        import warnings
        warnings.filterwarnings("ignore", message=".*incorrect regex pattern.*")

        # Point HF_HOME to bundled PromptGuard model directory so LlamaFirewall
        # finds it at $HF_HOME/meta-llama--Llama-Prompt-Guard-2-86M without downloading
        os.environ["HF_HOME"] = context.artifacts["prompt_guard_home"]

        # Initialize LlamaFirewall with PromptGuard scanner
        self.firewall = LlamaFirewall(
            scanners={Role.USER: [ScannerType.PROMPT_GUARD]}
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
        """Parse a safety category code (e.g. 'S1') into human-readable text."""
        if reason is None:
            return "Unknown"
        for item in self.unsafe_categories.split("\n"):
            if reason in item:
                stripped = item.strip()
                category = stripped.split(": ", 1)[1]
                category = category.split(".")[0]
                return category
        return "Unknown"

    def _invoke_prompt_guard(self, text: str) -> Dict[str, Any]:
        """
        Scan text using LlamaFirewall PromptGuard for jailbreaks/injections.

        Returns:
            Dict with 'flagged' (bool), 'label' (str), and 'raw_output' (str) keys
        """
        from llamafirewall import UserMessage

        result = self.firewall.scan(UserMessage(content=text))

        flagged = result.decision.value != "allow"

        return {
            "flagged": flagged,
            "label": "MALICIOUS" if flagged else "SAFE",
            "action": result.decision.value,
            "reason": str(result.reason) if result.reason else None,
            "raw_output": str(result)
        }

    def _invoke_llama_guard_4(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Invoke Llama Guard 4 to detect harmful content (text and/or images).

        Messages should have content in LG4 format — a list of content items:
          [{"type": "text", "text": "..."}, {"type": "image", "url": "..."}]

        Returns:
            Dict with 'flagged' (bool), 'label' (str), 'categories' (list),
            'category_names' (list), and 'raw_output' (str) keys
        """
        import torch

        inputs = self.lg4_processor.apply_chat_template(
            messages,
            add_generation_prompt=True,
            tokenize=True,
            return_dict=True,
            return_tensors="pt",
        ).to(self.device)

        with torch.no_grad():
            outputs = self.lg4_model.generate(
                **inputs,
                do_sample=False,
                max_new_tokens=100,
                cache_implementation="dynamic"
            )

        result = self.lg4_processor.batch_decode(
            outputs[:, inputs["input_ids"].shape[-1]:]
        )[0].strip()

        # Remove special tokens
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
            "raw_output": result
        }

    def _translate_input_guardrail_request(self, request: Dict[str, Any]):
        """
        Translates an OpenAI Chat Completions (ChatV1) request.

        Handles both text-only and multimodal (image + text) messages.
        OpenAI image_url format is translated to Llama Guard 4's expected format.

        Returns:
            Tuple of (text for PromptGuard, messages for Llama Guard 4)
        """
        if (request["mode"]["phase"] != "input") or (request["mode"]["stream_mode"] is None):
            raise Exception(f"Invalid mode: {request}.")
        if "messages" not in request:
            raise Exception(f"Missing key \"messages\" in request: {request}.")

        messages = request["messages"]
        combined_text = []
        formatted_messages = []

        for message in messages:
            if "content" not in message:
                raise Exception(f"Missing key \"content\" in \"messages\": {request}.")

            content = message["content"]
            role = message.get("role", "user")

            if isinstance(content, str):
                combined_text.append(content)
                formatted_messages.append({
                    "role": role,
                    "content": [{"type": "text", "text": content}]
                })
            elif isinstance(content, list):
                text_parts = []
                lg4_content = []
                for item in content:
                    if item.get("type") == "text":
                        text_parts.append(item["text"])
                        lg4_content.append({"type": "text", "text": item["text"]})
                    elif item.get("type") == "image_url":
                        # Translate OpenAI image_url format to LG4 image format
                        url = item["image_url"]["url"]
                        lg4_content.append({"type": "image", "url": url})
                    elif item.get("type") == "image":
                        # Already in LG4 format
                        lg4_content.append(item)
                if text_parts:
                    combined_text.append(" ".join(text_parts))
                if lg4_content:
                    formatted_messages.append({"role": role, "content": lg4_content})
            else:
                raise Exception(f"Invalid value type for \"content\": {request}")

        return " ".join(combined_text), formatted_messages

    def _translate_guardrail_response(self, pg_result: Dict[str, Any], lg4_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Combine PromptGuard and Llama Guard 4 results into Databricks Guardrails format.
        Rejects if EITHER scanner flags the input.
        """
        flagged = pg_result["flagged"] or lg4_result["flagged"]

        if flagged:
            reasons = []
            if pg_result["flagged"]:
                reasons.append(f"{pg_result['label']} (action: {pg_result['action']})")
            if lg4_result["flagged"]:
                categories_str = ", ".join(lg4_result["category_names"]) if lg4_result["category_names"] else "Unknown"
                category_codes = ", ".join(lg4_result["categories"]) if lg4_result["categories"] else "Unknown"
                reasons.append(f"{categories_str} ({category_codes})")

            reject_message = (
                f"🚫🚫🚫 Your request has been flagged by AI guardrails as potentially harmful. 🚫🚫🚫 "
                f"Detected Categories: {'; '.join(reasons)}"
            )

            return {
                "decision": "reject",
                "reject_message": reject_message,
                "guardrail_response": {
                    "include_in_response": True,
                    "response": {
                        "prompt_guard": pg_result,
                        "llama_guard_4": lg4_result
                    },
                    "finishReason": "input_guardrail_triggered"
                }
            }
        else:
            return {
                "decision": "proceed",
                "guardrail_response": {
                    "include_in_response": True,
                    "response": {
                        "prompt_guard": pg_result,
                        "llama_guard_4": lg4_result
                    }
                }
            }

    def predict(self, context, model_input, params=None):
        """Applies the guardrail to the model input and returns a guardrail response."""
        if isinstance(model_input, pd.DataFrame):
            model_input = model_input.to_dict("records")
            model_input = model_input[0]
            if not isinstance(model_input, dict):
                return {
                    "decision": "reject",
                    "reject_message": f"Could not parse model input: {model_input}",
                    "guardrail_response": {
                        "include_in_response": True,
                        "response": {"flagged": True, "label": "ERROR"}
                    }
                }
        elif not isinstance(model_input, dict):
            return {
                "decision": "reject",
                "reject_message": f"Could not parse model input: {model_input}",
                "guardrail_response": {
                    "include_in_response": True,
                    "response": {"flagged": True, "label": "ERROR"}
                }
            }

        try:
            text, messages = self._translate_input_guardrail_request(model_input)

            pg_result = self._invoke_prompt_guard(text)
            lg4_result = self._invoke_llama_guard_4(messages)

            result = self._translate_guardrail_response(pg_result, lg4_result)
            return result
        except Exception as e:
            return {
                "decision": "reject",
                "reject_message": f"Failed with an exception: {e}",
                "guardrail_response": {
                    "include_in_response": True,
                    "response": {"flagged": True, "label": "ERROR", "raw_output": str(e)}
                }
            }

set_model(LlamaFirewallInputModel())

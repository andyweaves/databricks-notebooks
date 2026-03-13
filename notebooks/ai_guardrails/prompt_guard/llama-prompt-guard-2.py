
"""Custom Guardrail using a Llama-Prompt-Guard-2 model.
This guardrail:
1. Translates OpenAI Chat Completions format to our internal format
2. Uses Llama-Prompt-Guard-2 to detect jailbreaks and prompt injections
3. Translates the model's response back to Databricks Guardrails format
"""

from typing import Any, Dict, List
import mlflow
from mlflow.models import set_model
import pandas as pd
import os

class LlamaPromptGuardModel(mlflow.pyfunc.PythonModel):
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.threshold = float(os.environ.get("GUARDRAIL_THRESHOLD", "0.85"))

    def load_context(self, context):
        """Load the Llama-Prompt-Guard model and tokenizer from artifacts."""
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        import torch

        model_path = context.artifacts["model_files"]

        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
        self.model.eval()

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)

    def _invoke_guardrail(self, input_text: str) -> Dict[str, Any]:
        """
        Invokes Llama-Prompt-Guard-2 model to detect jailbreaks and prompt injections.

        Prompt Guard 2 is a binary classifier:
        LABEL_0 = benign
        LABEL_1 = malicious (jailbreak or prompt injection)

        Returns:
            Dict with 'flagged' (bool), 'label' (str), and 'score' (float) keys
        """
        import torch

        inputs = self.tokenizer(
            input_text,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=512
        ).to(self.device)

        with torch.no_grad():
            logits = self.model(**inputs).logits
            probabilities = torch.softmax(logits, dim=-1)
            predicted_class_id = logits.argmax(dim=-1).item()
            label_map = {"LABEL_0": "SAFE", "LABEL_1": "MALICIOUS"} 
            raw_label = self.model.config.id2label[predicted_class_id]
            label = label_map.get(raw_label, raw_label)  
            malicious_score = probabilities[0][1].item()

        flagged = malicious_score >= self.threshold

        return {
            "flagged": flagged,
            "label": label,
            "score": malicious_score
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
        Translates the Llama-Prompt-Guard response to Databricks Guardrails format.
        """
        if response["flagged"]:
            reject_message = (
                f"🚫🚫🚫 Your request has been flagged by AI guardrails as a potential "
                f"jailbreak or prompt injection attempt (score: {response['score']:.3f}). 🚫🚫🚫"
            )

            return {
                "decision": "reject",
                "reject_message": reject_message,
                "guardrail_response": {
                    "include_in_response": True,
                    "response": response,
                    "finishReason": "input_guardrail_triggered"
                }
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
        if isinstance(model_input, pd.DataFrame):
            model_input = model_input.to_dict("records")
            model_input = model_input[0]
            if not isinstance(model_input, dict):
                return {"decision": "reject", "reject_message": f"Could not parse model input: {model_input}"}
        elif not isinstance(model_input, dict):
            return {"decision": "reject", "reject_message": f"Could not parse model input: {model_input}"}

        try:
            input_text = self._translate_input_guardrail_request(model_input)
            guardrail_response = self._invoke_guardrail(input_text)
            result = self._translate_guardrail_response(guardrail_response)
            return result
        except Exception as e:
            return {"decision": "reject", "reject_message": f"Failed with an exception: {e}"}

set_model(LlamaPromptGuardModel())

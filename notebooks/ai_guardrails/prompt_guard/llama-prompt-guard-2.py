
"""
Custom Guardrail using a Llama-Prompt-Guard-2 model.

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

    def load_context(self, context):
        """Load the Llama-Prompt-Guard model and tokenizer from artifacts."""
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        import torch
        
        # Load from the artifacts directory instead of downloading from HuggingFace
        model_path = context.artifacts["model_files"]
        
        # Load tokenizer and model from local path
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
        self.model.eval()
        
        # Set device
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)

    def _invoke_guardrail(self, input_text: str) -> Dict[str, Any]:
        """ 
        Invokes Llama-Prompt-Guard-2 model to detect jailbreaks and prompt injections.
        
        Returns:
            Dict with 'flagged' (bool) and 'label' (str) keys
        """
        import torch
        
        # Tokenize input
        inputs = self.tokenizer(
            input_text,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=512
        ).to(self.device)
        
        # Get model prediction
        with torch.no_grad():
            outputs = self.model(**inputs)
            logits = outputs.logits
            predicted_class = torch.argmax(logits, dim=-1).item()
        
        # Map class to label
        # Llama-Prompt-Guard-2 classes:
        # 0: SAFE
        # 1: JAILBREAK
        # 2: PROMPT_INJECTION
        label_map = {
            0: "SAFE",
            1: "JAILBREAK",
            2: "PROMPT_INJECTION"
        }
        
        label = label_map.get(predicted_class, "UNKNOWN")
        flagged = label != "SAFE"
        
        return {
            "flagged": flagged,
            "label": label,
            "confidence": torch.softmax(logits, dim=-1)[0][predicted_class].item()
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
                    # Note: Llama-Prompt-Guard is text-only, so we skip images
            else:
                raise Exception(f"Invalid value type for \"content\": {request}")
        
        return " ".join(combined_text)
    
    def _translate_guardrail_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translates the Llama-Prompt-Guard response to Databricks Guardrails format.
        """
        if response["flagged"]:
            label = response["label"]
            if label == "JAILBREAK":
                reject_message = f"Your request has been flagged by our AI guardrails as a potential jailbreak attempt: {response}" 
            elif label == "PROMPT_INJECTION":
                reject_message = f"Your request has been flagged by our AI guardrails as a potential prompt injection attempt: {response}" 
            else:
                reject_message = f"Your request has been flagged by our AI guardrails: {response}" 
            
            return {
                "decision": "reject",
                "reject_message": reject_message
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
            assert isinstance(model_input, dict)
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
      
set_model(LlamaPromptGuardModel())


"""
Custom Guardrail using Llama Guard 4.

This guardrail:
1. Translates OpenAI Chat Completions format to our internal format
2. Uses Llama Guard 4 to detect unsafe content
3. Translates the model's response back to Databricks Guardrails format

IMPORTANT: Based on my tests, the output returned by llama guard 4 is not very deterministic. It can be both upper and lower case, have both leading and trailing special characters and can include and not include the categories. Sometimes it just returns random text in another language! We're applying various transformations to try and make the output more deterministic below (such stripping special characters and lower casing input text). Please review the code so they are understood - they may not work for every use case.
"""

import mlflow
from mlflow.models import set_model
import pandas as pd
from typing import Any, Dict, List
import logging

# Set up logging
logger = logging.getLogger(__name__)

class LlamaGuard4Model(mlflow.pyfunc.PythonModel):
    def __init__(self):
        self.model = None
        self.processor = None
        self.config = None
        self.category_descriptions = {
            "S1": "Violent Crimes",
            "S2": "Non-Violent Crimes",
            "S3": "Sex-Related Crimes",
            "S4": "Child Sexual Exploitation",
            "S5": "Defamation",
            "S6": "Specialized Advice",
            "S7": "Privacy",
            "S8": "Intellectual Property",
            "S9": "Indiscriminate Weapons",
            "S10": "Hate",
            "S11": "Suicide & Self-Harm",
            "S12": "Sexual Content",
            "S13": "Elections",
            "S14": "Code Interpreter Abuse"
        }
        
    def load_context(self, context):
        """Load the Llama Guard 4 model and processor from artifacts."""
        from transformers import AutoProcessor, Llama4ForConditionalGeneration, AutoConfig
        import torch
        
        # Load from the artifacts directory
        model_path = context.artifacts["model_files"]
        
        # Load processor and model from local path
        self.config = AutoConfig.from_pretrained(model_path)
        self.config.text_config.attention_chunk_size = 8192

        self.processor = AutoProcessor.from_pretrained(model_path)

        self.model = Llama4ForConditionalGeneration.from_pretrained(
          model_path,
          torch_dtype=torch.bfloat16, # For better precision use torch.float32
          config=self.config)
        self.model.eval()
        
        # Set device
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        
        logger.info(f"Llama Guard 4 model loaded on {self.device}")
    
    def _format_conversation_for_llama_guard(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """ 
        Formats messages into Llama Guard 4 expected conversation format.
        Llama Guard 4 uses the processor's apply_chat_template method.
        """
        formatted_messages = []
        
        for message in messages:
            role = message.get("role", "user")
            content = message.get("content", "")
            
            # Extract text from content (handle both string and list formats)
            if isinstance(content, str):
                text = content
            elif isinstance(content, list):
                text_parts = []
                for item in content:
                    if item.get("type") == "text":
                        text_parts.append(item["text"])
                text = " ".join(text_parts)
            else:
                text = str(content)
            
            # We need to lowercase the text for Llama Guard 4, for some reason capitalisation really impacts the detection rates
            formatted_messages.append({
                "role": role,
                "content": [{"type": "text", "text": text.lower()}]
            })
        
        return formatted_messages

    def _invoke_guardrail(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        """ 
        Invokes Llama Guard 4 model to detect harmful content.
        
        Returns:
            Dict with 'safe' (bool), 'categories' (list), and 'raw_output' (str) keys
        """
        import torch
        
        # Apply chat template
        inputs = self.processor.apply_chat_template(
            messages,
            tokenize=True,
            add_generation_prompt=True,
            return_tensors="pt",
            return_dict=True,
        ).to(self.device)
        
        # Get model prediction
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=100,
                do_sample=False,
            )
        
        # Decode output (skip the input tokens)
        output_text = self.processor.batch_decode(
            outputs[:, inputs["input_ids"].shape[-1]:], 
            skip_special_tokens=True
        )[0]
        
        # Based on my tests, the output returned by llama guard 4 is not very deterministic. It can be both upper and lower case, have both leading and trailing special characters and can include and not include the categories. Sometimes it just returns random text in another language! Trying to make the output as deterministic as possible below... 

        if output_text.strip().lower().startswith("safe"):
            return {
                "safe": True,
                "raw_output": output_text.upper()
            }
        elif output_text.strip().lower().startswith("unsafe"):
            return {
                "safe": False,
                "raw_output": output_text.upper()
            }
        else:
            # Unexpected output format
            logger.warn(f"Unexpected output format: {output_text}")
            return {
                "safe": False,
                "raw_output": f"Unexpected output format: {output_text}"
            }

    def _translate_input_guardrail_request(self, request: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Translates an OpenAI Chat Completions (ChatV1) request to Llama Guard 4 format.
        """
        if (request["mode"]["phase"] != "input") or (request["mode"]["stream_mode"] is None):
            raise Exception(f"Invalid mode: {request}.")
        if ("messages" not in request):
            raise Exception(f"Missing key \"messages\" in request: {request}.")
        
        messages = request["messages"]
        return self._format_conversation_for_llama_guard(messages)
    
    def _translate_guardrail_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translates the Llama Guard 4 response to Databricks Guardrails format.
        """
        if not response["safe"]:
            
            reject_message = f"🚫🚫🚫 Your request has been flagged as UNSAFE by AI guardrails. 🚫🚫🚫 Response: {response['raw_output']}"
            
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
            formatted_messages = self._translate_input_guardrail_request(model_input)
            
            # Invoke guardrail with ensemble approach
            guardrail_response = self._invoke_guardrail(formatted_messages)
            
            # Translate response
            result = self._translate_guardrail_response(guardrail_response)
            return result
        except Exception as e:
            logger.error(f"Guardrail failed: {e}")
            return {"decision": "reject", "reject_message": f"Failed with an exception: {e}"}

set_model(LlamaGuard4Model())

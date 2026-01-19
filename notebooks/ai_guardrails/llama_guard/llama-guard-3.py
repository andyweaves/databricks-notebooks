"""
Custom Guardrail using Llama Guard 3 model.

This guardrail:
1. Translates OpenAI Chat Completions format to Llama Guard 3 format
2. Uses Llama Guard 3 to detect harmful content across 14 safety categories
3. Parses safety categories and translates the response to Databricks Guardrails format
"""
from typing import Any, Dict, List
import mlflow
from mlflow.models import set_model
import pandas as pd
import os
import re

class LlamaGuard3Model(mlflow.pyfunc.PythonModel):
    def __init__(self):
        self.model = None
        self.tokenizer = None
        # Define Llama Guard 3 safety categories
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
        """Load the Llama Guard 3 model and tokenizer from artifacts."""
        from transformers import AutoTokenizer, AutoModelForCausalLM
        import torch
        
        # Load from the artifacts directory
        model_path = context.artifacts["model_files"]
        
        # Load tokenizer and model from local path
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForCausalLM.from_pretrained(model_path)
        self.model.eval()
        
        # Set device
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)

    def parse_category(self, reason: str) -> str:
        """
        Parse the safety category code (e.g., 'S1', 'S10') into human-readable text.
        
        Args:
            reason: Category code like 'S1', 'S2', etc.
            
        Returns:
            Human-readable category name
        """
        if reason is None:
            return "Unknown"
        
        for item in self.unsafe_categories.split("\n"):
            if reason in item:
                stripped = item.strip()
                category = stripped.split(": ", 1)[1]
                category = category.split(".")[0]
                return category
        return "Unknown"

    def _format_llama_guard_input(self, messages: List[Dict[str, str]]) -> str:
        """
        Manually format input for Llama Guard 3.
        The apply_chat_template method doesn't properly include the conversation,
        so we need to construct the prompt manually.
        
        Args:
            messages: List of message dictionaries with 'role' and 'content'
            
        Returns:
            Formatted prompt string for Llama Guard 3
        """
        # Build the conversation section
        conversation = ""
        for msg in messages:
            role = msg["role"].capitalize()
            content = msg["content"]
            conversation += f"{role}: {content}\n\n"
        
        # Full prompt template for Llama Guard 3
        prompt = f"""<|begin_of_text|><|start_header_id|>user<|end_header_id|>

Task: Check if there is unsafe content in 'User' messages in conversations according our safety policy with the below categories.

<BEGIN UNSAFE CONTENT CATEGORIES>
S1: Violent Crimes.
S2: Non-Violent Crimes.
S3: Sex Crimes.
S4: Child Exploitation.
S5: Defamation.
S6: Specialized Advice.
S7: Privacy.
S8: Intellectual Property.
S9: Indiscriminate Weapons.
S10: Hate.
S11: Self-Harm.
S12: Sexual Content.
S13: Elections.
S14: Code Interpreter Abuse.
<END UNSAFE CONTENT CATEGORIES>

<BEGIN CONVERSATION>

{conversation.strip()}

<END CONVERSATION>

Provide your safety assessment for ONLY THE LAST User message in the above conversation:
 - First line must read'safe' or 'unsafe'.
 - If unsafe, a second line must include a comma-separated list of violated categories. <|eot_id|><|start_header_id|>assistant<|end_header_id|>

"""
        return prompt

    def _invoke_guardrail(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """ 
        Invokes Llama Guard 3 model to detect harmful content.
        
        Args:
            messages: List of message dictionaries with 'role' and 'content'
            
        Returns:
            Dict with 'flagged' (bool), 'label' (str), and 'categories' (list) keys
        """
        import torch
        
        # Format input manually for Llama Guard 3
        formatted_input = self._format_llama_guard_input(messages)
        
        # Tokenize the input
        inputs = self.tokenizer(
            formatted_input,
            return_tensors="pt"
        ).to(self.device)
        
        # Get model prediction
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                do_sample=False,
                max_new_tokens=100
            )
        
        # Decode the output (only the generated part)
        result = self.tokenizer.decode(
            outputs[0][inputs["input_ids"].shape[-1]:]
        ).strip()
        
        # Remove special tokens
        result = result.replace("<|eot_id|>", "").strip()
        
        # Parse the result
        # Format: "safe" or "unsafe\nS1\nS2" (categories on new lines)
        flagged = result.lower().startswith("unsafe")
        
        categories = []
        category_names = []
        
        if flagged:
            # Extract category codes (S1, S2, etc.)
            lines = result.split("\n")
            for line in lines[1:]:  # Skip first line which is "unsafe"
                line = line.strip()
                if line and line.startswith("S"):
                    categories.append(line)
                    category_names.append(self.parse_category(line))
        
        return {
            "flagged": flagged,
            "label": "UNSAFE" if flagged else "SAFE",
            "categories": categories,
            "category_names": category_names,
            "raw_output": result
        }
    
    def _translate_input_guardrail_request(self, request: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Translates an OpenAI Chat Completions (ChatV1) request to Llama Guard 3 format.
        
        Args:
            request: Guardrail request dictionary
            
        Returns:
            List of message dictionaries for Llama Guard 3
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
                # Combine text content from list
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
        Translates the Llama Guard 3 response to Databricks Guardrails format.
        
        Args:
            response: Guardrail response from _invoke_guardrail
            
        Returns:
            Databricks Guardrails formatted response
        """
        if response["flagged"]:
            categories_str = ", ".join(response["category_names"]) if response["category_names"] else "Unknown"
            category_codes = ", ".join(response["categories"]) if response["categories"] else "Unknown"
            
            reject_message = (
                f"🚫🚫🚫 Your request has been flagged by AI guardrails as potentially harmful. 🚫🚫🚫 " +
                f"Detected categories: {categories_str} ({category_codes})"
            )
            
            return {
                "decision": "reject",
                "reject_message": reject_message,
                "guardrail_response": {
                    "include_in_response": True,
                    "response": response
                }
            }
        else:
            return {
                "decision": "proceed",
                "guardrail_response": {
                    "include_in_response": True,
                    "response": response
                }
            }

    def predict(self, context, model_input, params=None):
        """
        Applies the guardrail to the model input and returns a guardrail response.
        
        Args:
            context: MLflow context
            model_input: Input data (DataFrame or dict)
            params: Optional parameters
            
        Returns:
            Guardrail response dictionary
        """
        # Convert DataFrame to dict if needed
        if isinstance(model_input, pd.DataFrame):
            model_input = model_input.to_dict("records")
            model_input = model_input[0]
            assert isinstance(model_input, dict)
        elif not isinstance(model_input, dict):
            return {
                "decision": "reject",
                "reject_message": f"Could not parse model input: {model_input}"
            }
          
        try:
            # Translate input to Llama Guard 3 format
            messages = self._translate_input_guardrail_request(model_input)
            
            # Invoke guardrail
            guardrail_response = self._invoke_guardrail(messages)
            
            # Translate response to Databricks format
            result = self._translate_guardrail_response(guardrail_response)
            return result
        except Exception as e:
            return {
                "decision": "reject",
                "reject_message": f"Failed with an exception: {e}"
            }
      
set_model(LlamaGuard3Model())

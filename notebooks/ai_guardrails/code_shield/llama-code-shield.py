
"""
To define a custom guardrail pyfunc, the following must be implemented:
1. def _translate_output_guardrail_request(self, model_input) -> Translates the model input between an OpenAI Chat Completions (ChatV1, https://platform.openai.com/docs/api-reference/chat/create) response and our custom guardrails format.
2. def invoke_guardrail(self, input) -> Invokes our custom moderation logic.
3. def _translate_guardrail_response(self, response, sanitized_input) -> Translates our custom guardrails response to the OpenAI Chat Completions (ChatV1) format.
4. def predict(self, context, model_input, params) -> Applies the guardrail to the model input/output and returns the guardrail response.
"""
from typing import Any, Dict, List, Union
import json
import copy
import mlflow
from mlflow.models import set_model
import os
import pandas as pd
import asyncio
from codeshield.cs import CodeShield

class CodeShieldGuardrail(mlflow.pyfunc.PythonModel):
    def __init__(self):
      pass

    async def _invoke_guardrail_async(self, code_content: str):
      """ 
      Invokes Code Shield to scan code for security issues.
      Returns the scan result.
      """
      result = await CodeShield.scan_code(code_content)
      return result

    def _invoke_guardrail(self, code_content: str):
      """ 
      Synchronous wrapper for Code Shield scanning.
      """
      loop = None
      try:
        # Try to get the existing event loop
        try:
          loop = asyncio.get_running_loop()
        except RuntimeError:
          # No running loop, create a new one
          loop = asyncio.new_event_loop()
          asyncio.set_event_loop(loop)
          
        # Run the async function
        if loop.is_running():
          # If loop is already running, create a task
          import nest_asyncio
          nest_asyncio.apply()
          result = loop.run_until_complete(self._invoke_guardrail_async(code_content))
        else:
          result = loop.run_until_complete(self._invoke_guardrail_async(code_content))
        
        return result
      except Exception as e:
        # Ensure we don't reference coroutines in error messages
        error_msg = str(e)
        raise Exception(f"Code Shield scan failed: {error_msg}")

    def _translate_output_guardrail_request(self, request: dict):
      """
      Translates a OpenAI Chat Completions (ChatV1) response to extract code content.
      """
      if (request["mode"]["phase"] != "output") or (request["mode"]["stream_mode"] is None) or (request["mode"]["stream_mode"] == "streaming"):
        raise Exception(f"Invalid mode: {request}.")
      if ("choices" not in request):
        raise Exception(f"Missing key \\"choices\\" in request: {request}.")
      
      choices = request["choices"]
      code_content = ""

      for choice in choices:
        # Performing validation
        if ("message" not in choice):
          raise Exception(f"Missing key \\"message\\" in \\"choices\\": {request}.")
        if ("content" not in choice["message"]):
          raise Exception(f"Missing key \\"content\\" in \\"choices[\\"message\\"]\\": {request}.")

        # Extract code content from the message
        code_content += choice["message"]["content"]

      return code_content

    def _translate_guardrail_response(self, scan_result, original_content):
      """
      Translates Code Shield scan results to the Databricks Guardrails format.
      """
      if scan_result.is_insecure:
        if scan_result.recommended_treatment == "block":
          # Block the response entirely
          return {
            "decision": "reject",
            "reject_reason": f"🚫🚫🚫 The generated code has been flagged as insecure by AI guardrails. 🚫🚫🚫",
            "guardrail_response": {"include_in_response": True, "response": scan_result}
          }
        elif scan_result.recommended_treatment == "warn":
          # Add warning to the content
          warning_message = "⚠️⚠️⚠️ WARNING: The generated code has been flagged as having potential security issues by AI guardrails. Please review carefully before use. ⚠️⚠️⚠️"
          return {
            "decision": "sanitize",
            "guardrail_response": {"include_in_response": True, "response": scan_result}
            "sanitized_input": {
              "choices": [{
                "message": {
                  "role": "assistant",
                  "content": warning_message + "\n" + original_content
                }
              }]
            }
          }
      
      # No security issues found
      return {
        "decision": "proceed",
        "guardrail_response": {"include_in_response": True, "response": scan_result}
      }

    def predict(self, context, model_input, params):
        """
        Applies the Code Shield guardrail to the model output and returns the guardrail response. 
        """

        # The input to this model will be converted to a Pandas DataFrame when the model is served
        if (isinstance(model_input, pd.DataFrame)):
            model_input = model_input.to_dict("records")
            model_input = model_input[0]
            assert(isinstance(model_input, dict))
        elif (not isinstance(model_input, dict)):
            return {"decision": "reject", "reject_reason": f"Couldn't parse model input: {model_input}"}
          
        try:
          code_content = self._translate_output_guardrail_request(model_input)
          scan_result = self._invoke_guardrail(code_content)
          result = self._translate_guardrail_response(scan_result, code_content) 
          return result
        except Exception as e:
          # Convert exception to string to avoid coroutine references
          error_message = str(e)
          return {"decision": "reject", "reject_reason": f"Errored with the following error message: {error_message}"}
      
set_model(CodeShieldGuardrail())

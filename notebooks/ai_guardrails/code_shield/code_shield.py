# Databricks notebook source
# MAGIC %md
# MAGIC # Deploy [Llama Code Shield](https://www.llama.com/llama-protections/) on Databricks
# MAGIC For use with [AI Gateway](https://www.databricks.com/product/artificial-intelligence/ai-gateway) as a custom (output) guardrail
# MAGIC
# MAGIC ## About Llama Code Shield
# MAGIC
# MAGIC Code Shield provides support for inference-time filtering of insecure code produced by LLMs. This offers mitigation of insecure code suggestions risk and secure command execution for 7 programming languages with an average latency of 200ms.

# COMMAND ----------

!pip install mlflow==3.8.1
!pip install codeshield==1.0.1
dbutils.library.restartPython()

# COMMAND ----------

from databricks.sdk import WorkspaceClient

ws = WorkspaceClient()

catalogs = [x.full_name for x in list(ws.catalogs.list())]
dbutils.widgets.dropdown("catalog", defaultValue=catalogs[0], choices=catalogs[:1000], label="Catalog")
schemas = [x.name for x in list(ws.schemas.list(catalog_name=dbutils.widgets.get("catalog")))]
dbutils.widgets.dropdown("schema", defaultValue=schemas[0], choices=schemas[:1000], label="Schema")
dbutils.widgets.text(name="model_serving_endpoint", defaultValue="llama-code-shield", label="Model serving endpoint to deploy model to")
dbutils.widgets.text(name="model_name", defaultValue="llama_code_shield", label="Model name to register to UC")

model_serving_endpoint = dbutils.widgets.get("model_serving_endpoint")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1: Create a class for our custom guardrail

# COMMAND ----------

# DBTITLE 1,Cell 6
# MAGIC %%writefile "{model_serving_endpoint}.py"
# MAGIC
# MAGIC """
# MAGIC To define a custom guardrail pyfunc, the following must be implemented:
# MAGIC 1. def _translate_output_guardrail_request(self, model_input) -> Translates the model input between an OpenAI Chat Completions (ChatV1, https://platform.openai.com/docs/api-reference/chat/create) response and our custom guardrails format.
# MAGIC 2. def invoke_guardrail(self, input) -> Invokes our custom moderation logic.
# MAGIC 3. def _translate_guardrail_response(self, response, sanitized_input) -> Translates our custom guardrails response to the OpenAI Chat Completions (ChatV1) format.
# MAGIC 4. def predict(self, context, model_input, params) -> Applies the guardrail to the model input/output and returns the guardrail response.
# MAGIC """
# MAGIC
# MAGIC from typing import Any, Dict, List, Union
# MAGIC import json
# MAGIC import copy
# MAGIC import mlflow
# MAGIC from mlflow.models import set_model
# MAGIC import os
# MAGIC import pandas as pd
# MAGIC import asyncio
# MAGIC from codeshield.cs import CodeShield
# MAGIC
# MAGIC class CodeShieldGuardrail(mlflow.pyfunc.PythonModel):
# MAGIC     def __init__(self):
# MAGIC       pass
# MAGIC
# MAGIC     async def _invoke_guardrail_async(self, code_content: str):
# MAGIC       """ 
# MAGIC       Invokes Code Shield to scan code for security issues.
# MAGIC       Returns the scan result.
# MAGIC       """
# MAGIC       result = await CodeShield.scan_code(code_content)
# MAGIC       return result
# MAGIC
# MAGIC     def _invoke_guardrail(self, code_content: str):
# MAGIC       """ 
# MAGIC       Synchronous wrapper for Code Shield scanning.
# MAGIC       """
# MAGIC       loop = None
# MAGIC       try:
# MAGIC         # Try to get the existing event loop
# MAGIC         try:
# MAGIC           loop = asyncio.get_running_loop()
# MAGIC         except RuntimeError:
# MAGIC           # No running loop, create a new one
# MAGIC           loop = asyncio.new_event_loop()
# MAGIC           asyncio.set_event_loop(loop)
# MAGIC           
# MAGIC         # Run the async function
# MAGIC         if loop.is_running():
# MAGIC           # If loop is already running, create a task
# MAGIC           import nest_asyncio
# MAGIC           nest_asyncio.apply()
# MAGIC           result = loop.run_until_complete(self._invoke_guardrail_async(code_content))
# MAGIC         else:
# MAGIC           result = loop.run_until_complete(self._invoke_guardrail_async(code_content))
# MAGIC         
# MAGIC         return result
# MAGIC       except Exception as e:
# MAGIC         # Ensure we don't reference coroutines in error messages
# MAGIC         error_msg = str(e)
# MAGIC         raise Exception(f"Code Shield scan failed: {error_msg}")
# MAGIC
# MAGIC     def _translate_output_guardrail_request(self, request: dict):
# MAGIC       """
# MAGIC       Translates a OpenAI Chat Completions (ChatV1) response to extract code content.
# MAGIC       """
# MAGIC       if (request["mode"]["phase"] != "output") or (request["mode"]["stream_mode"] is None) or (request["mode"]["stream_mode"] == "streaming"):
# MAGIC         raise Exception(f"Invalid mode: {request}.")
# MAGIC       if ("choices" not in request):
# MAGIC         raise Exception(f"Missing key \"choices\" in request: {request}.")
# MAGIC       
# MAGIC       choices = request["choices"]
# MAGIC       code_content = ""
# MAGIC
# MAGIC       for choice in choices:
# MAGIC         # Performing validation
# MAGIC         if ("message" not in choice):
# MAGIC           raise Exception(f"Missing key \"message\" in \"choices\": {request}.")
# MAGIC         if ("content" not in choice["message"]):
# MAGIC           raise Exception(f"Missing key \"content\" in \"choices[\"message\"]\": {request}.")
# MAGIC
# MAGIC         # Extract code content from the message
# MAGIC         code_content += choice["message"]["content"]
# MAGIC
# MAGIC       return code_content
# MAGIC
# MAGIC     def _translate_guardrail_response(self, scan_result, original_content):
# MAGIC       """
# MAGIC       Translates Code Shield scan results to the Databricks Guardrails format.
# MAGIC       """
# MAGIC       # Convert scan_result to a JSON-serializable dictionary
# MAGIC       # Extract the string value from the enum
# MAGIC       treatment_value = scan_result.recommended_treatment
# MAGIC       if hasattr(treatment_value, 'value'):
# MAGIC         treatment_str = treatment_value.value
# MAGIC       else:
# MAGIC         treatment_str = str(treatment_value)
# MAGIC       
# MAGIC       scan_result_dict = {
# MAGIC         "is_insecure": bool(scan_result.is_insecure),
# MAGIC         "recommended_treatment": treatment_str
# MAGIC       }
# MAGIC       
# MAGIC       if scan_result.is_insecure:
# MAGIC         if treatment_str == "block":
# MAGIC           # Block the response entirely
# MAGIC           return {
# MAGIC             "decision": "reject",
# MAGIC             "reject_message": f"""🚫🚫🚫 The generated code has been flagged as insecure by AI guardrails. 🚫🚫🚫
# MAGIC             Scan result: 
# MAGIC             {scan_result.__dict__}
# MAGIC             """
# MAGIC           }
# MAGIC         elif treatment_str == "warn":
# MAGIC           # Add warning to the content
# MAGIC           warning_message = "⚠️⚠️⚠️ WARNING: The generated code has been flagged as having potential security issues by AI guardrails. Please review carefully before use. ⚠️⚠️⚠️"
# MAGIC           return {
# MAGIC             "decision": "sanitize",
# MAGIC             "guardrail_response": {"include_in_response": True, "response": warning_message, "scan_result": scan_result.__dict__},
# MAGIC             "sanitized_input": {
# MAGIC               "choices": [{
# MAGIC                 "message": {
# MAGIC                   "role": "assistant",
# MAGIC                   "content": original_content
# MAGIC                 }
# MAGIC               }]
# MAGIC             }
# MAGIC           }
# MAGIC       
# MAGIC       # No security issues found
# MAGIC       return {
# MAGIC         "decision": "proceed",
# MAGIC         "guardrail_response": {"include_in_response": True, "response": scan_result.__dict__}
# MAGIC       }
# MAGIC
# MAGIC     def predict(self, context, model_input, params):
# MAGIC         """
# MAGIC         Applies the Code Shield guardrail to the model output and returns the guardrail response. 
# MAGIC         """
# MAGIC
# MAGIC         # The input to this model will be converted to a Pandas DataFrame when the model is served
# MAGIC         if (isinstance(model_input, pd.DataFrame)):
# MAGIC             model_input = model_input.to_dict("records")
# MAGIC             model_input = model_input[0]
# MAGIC             assert(isinstance(model_input, dict))
# MAGIC         elif (not isinstance(model_input, dict)):
# MAGIC             return {"decision": "reject", "reject_reason": f"Couldn't parse model input: {model_input}"}
# MAGIC           
# MAGIC         try:
# MAGIC           code_content = self._translate_output_guardrail_request(model_input)
# MAGIC           scan_result = self._invoke_guardrail(code_content)
# MAGIC           result = self._translate_guardrail_response(scan_result, code_content) 
# MAGIC           return result
# MAGIC         except Exception as e:
# MAGIC           # Convert exception to string to avoid coroutine references
# MAGIC           error_message = str(e)
# MAGIC           return {"decision": "reject", "reject_reason": f"Errored with the following error message: {error_message}"}
# MAGIC       
# MAGIC set_model(CodeShieldGuardrail())

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2: Log the model to MLflow and register it to UC

# COMMAND ----------

# DBTITLE 1,Cell 7
import mlflow
import logging

logging.getLogger("mlflow").setLevel(logging.ERROR)
model_input_example = {
  "choices": [
      {
        "index": 0,
        "message": {
            "role": "assistant",
            "content": "def hash_password(password):\n    return hashlib.md5(password.encode()).hexdigest()",
            "refusal": None,
            "annotations": [],
        },
        "logprobs": None,
        "finish_reason": "stop",
      }
    ],
  "mode": {
    "phase": "output",
    "stream_mode": "non_streaming"
  }
}

pyfunc_model_path = f"{model_serving_endpoint}.py"
registered_model_path = f"{dbutils.widgets.get('catalog')}.{dbutils.widgets.get('schema')}.{dbutils.widgets.get('model_name')}"

with mlflow.start_run():
    model_info = mlflow.pyfunc.log_model(
        artifact_path=model_serving_endpoint,
        python_model=pyfunc_model_path,
        metadata={
            "task": "llm/v1/chat",
        },
        input_example=model_input_example,
        registered_model_name=registered_model_path,
        pip_requirements=[
            "mlflow==3.8.1",
            "codeshield==1.0.1",
            "nest-asyncio==1.6.0"
        ]
    )

print(f"✅ Model logged to: {model_info.model_uri}")
print(f"✅ Model registered as: {registered_model_path}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 4: Test the model 
# MAGIC Test the model with various inputs to ensure that it's working correctly

# COMMAND ----------

# Load the model
loaded_model = mlflow.pyfunc.load_model(model_info.model_uri)

print("Testing sanitize content...")
response = loaded_model.predict(model_input_example)
print(f"Sanitize content response: {response}")
assert "decision" in response
assert response["decision"] == "sanitize", "Sanitize content should be subject to a warning"

print("Testing insecure content...")

insecure_content = {
  "choices": [
      {
        "index": 0,
        "message": {
            "role": "assistant",
             "content": """void vulnerable_function(char *user_input) {
              char buffer[50];
              strcpy(buffer, user_input);  // Not checking about length
              printf("User input: %s\n", buffer);
            }
            
            int main() {
              char input[100];
              printf("Enter input: ");
              gets(input); // Unsafe function
              vulnerable_function(input);
              return 0;
              }""",
            "refusal": None,
            "annotations": [],
        },
        "logprobs": None,
        "finish_reason": "stop",
      }
    ],
  "mode": {
    "phase": "output",
    "stream_mode": "non_streaming"
  }
}

response = loaded_model.predict(insecure_content)

print(f"Insecure content response: {response}")
assert "decision" in response
assert response["decision"] == "reject", "Insecure content should be rejected"

print("\n✅ All validation tests completed!")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 5: Deploy to Model Serving
# MAGIC
# MAGIC Now deploy the model to a serving endpoint for use with AI Gateway.

# COMMAND ----------

from databricks.sdk.service.serving import EndpointCoreConfigInput, ServedEntityInput
from datetime import timedelta

# Create or update the serving endpoint
try:
    ws.serving_endpoints.create_and_wait(
        name=model_serving_endpoint,
        config=EndpointCoreConfigInput(
            served_entities=[
                ServedEntityInput(
                    entity_name=registered_model_path,
                    entity_version=model_info.registered_model_version, 
                    workload_size="Small",
                    scale_to_zero_enabled=True
                )
            ]
        ),
        timeout=timedelta(minutes=60)
    )
    print(f"✅ Serving endpoint '{model_serving_endpoint}' created successfully!")
    
except Exception as e:
    if "already exists" in str(e):
        print(f"Endpoint '{model_serving_endpoint}' already exists. Updating...")
        ws.serving_endpoints.update_config_and_wait(
            name=model_serving_endpoint,
            served_entities=[
                ServedEntityInput(
                    entity_name=registered_model_path,
                    entity_version=model_info.registered_model_version, 
                    workload_size="Small",
                    scale_to_zero_enabled=True,
                )
            ],
            timeout=timedelta(minutes=60)
        )
        print(f"✅ Serving endpoint '{model_serving_endpoint}' updated successfully!")
    else:
        raise e

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 6: Use the model for inference

# COMMAND ----------

import json

# Convert inputs to ensure JSON compatibility (handles numpy int64 types)
serializable_content = json.loads(json.dumps(insecure_content, default=int))

response = ws.serving_endpoints.query(
    name=model_serving_endpoint,
    inputs=serializable_content
)
print(f"✅ Model serving endpoint query successfully: \n{response.predictions}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 7: Add the model serving endpoint as a custom guardrail
# MAGIC
# MAGIC ![Custom Guardrail.png](./Custom Guardrail.png "Custom Guardrail.png")
# MAGIC
# MAGIC ## Step 8: Use your foundation model for inference
# MAGIC
# MAGIC ![Inference Guardrail.png](./Inference Guardrail.png "Inference Guardrail.png")

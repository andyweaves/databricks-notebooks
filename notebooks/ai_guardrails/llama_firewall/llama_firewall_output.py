# Databricks notebook source
# MAGIC %md
# MAGIC # Deploy [LlamaFirewall](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall) (CodeShield) on Databricks
# MAGIC For use with [AI Gateway](https://www.databricks.com/product/artificial-intelligence/ai-gateway) as a custom (output) guardrail
# MAGIC
# MAGIC ## About LlamaFirewall CodeShield Scanner
# MAGIC
# MAGIC LlamaFirewall's CodeShield scanner provides inference-time filtering of insecure LLM-generated code
# MAGIC using Semgrep and regex-based static analysis rules across 8 programming languages, covering 50+ CWEs.
# MAGIC
# MAGIC ### Key Differences from Standalone Code Shield
# MAGIC | Aspect | Standalone Code Shield | LlamaFirewall (CodeShield) |
# MAGIC |--------|----------------------|---------------------------|
# MAGIC | Install | `pip install codeshield==1.0.1` | `pip install llamafirewall` (includes CodeShield) |
# MAGIC | Async handling | Manual `nest_asyncio` + event loop management | Handled internally by LlamaFirewall |
# MAGIC | Config | Custom async wrapper class | Declarative scanner assignment per role |
# MAGIC | Extensibility | Single-purpose code scanning | Add PromptGuard/AlignmentCheck with one line |
# MAGIC
# MAGIC ### Prerequisites
# MAGIC - **Compute**: CPU-based (Small workload)
# MAGIC - No HuggingFace token required (CodeShield uses rule-based analysis, not ML models)

# COMMAND ----------

!pip install mlflow==3.8.1
!pip install llamafirewall
dbutils.library.restartPython()

# COMMAND ----------

from databricks.sdk import WorkspaceClient

ws = WorkspaceClient()

catalogs = [x.full_name for x in list(ws.catalogs.list())]
dbutils.widgets.dropdown("catalog", defaultValue=catalogs[0], choices=catalogs[:1000], label="Catalog")
schemas = [x.name for x in list(ws.schemas.list(catalog_name=dbutils.widgets.get("catalog")))]
dbutils.widgets.dropdown("schema", defaultValue=schemas[0], choices=schemas[:1000], label="Schema")
dbutils.widgets.text(name="model_serving_endpoint", defaultValue="llama-firewall-output", label="Model serving endpoint to deploy model to")
dbutils.widgets.text(name="model_name", defaultValue="llama_firewall_output", label="Model name to register to UC")

model_serving_endpoint = dbutils.widgets.get("model_serving_endpoint")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1: Verify LlamaFirewall Installation
# MAGIC
# MAGIC CodeShield uses rule-based static analysis (Semgrep + regex), so no ML model downloads are needed.

# COMMAND ----------

# DBTITLE 1,Validate CodeShield Scanner
from llamafirewall import LlamaFirewall, AssistantMessage, Role, ScannerType

firewall = LlamaFirewall(
    scanners={
        Role.ASSISTANT: [ScannerType.CODE_SHIELD],
    }
)

# Quick test with safe code
test_result = firewall.scan(AssistantMessage(content="def hello():\n    print('Hello, world!')"))
print(f"✅ LlamaFirewall CodeShield initialized successfully!")
print(f"Test scan result: action={test_result.action.value}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2: Create a class for our custom guardrail
# MAGIC
# MAGIC Note: Unlike the standalone Code Shield deployment which requires manual `nest_asyncio`
# MAGIC and event loop management, LlamaFirewall handles async internally.

# COMMAND ----------

# MAGIC %%writefile "{model_serving_endpoint}.py"
# MAGIC
# MAGIC """
# MAGIC Custom Output Guardrail using LlamaFirewall (CodeShield scanner).
# MAGIC
# MAGIC LlamaFirewall is Meta's unified guardrail framework that orchestrates multiple
# MAGIC security scanners. This model class uses the CodeShield scanner to detect
# MAGIC insecure LLM-generated code.
# MAGIC
# MAGIC Compared to deploying Code Shield standalone:
# MAGIC - LlamaFirewall wraps CodeShield with a unified policy engine
# MAGIC - Same underlying Semgrep + regex-based static analysis
# MAGIC - Covers 50+ CWEs across 8 programming languages
# MAGIC - Declarative configuration via scanner assignments
# MAGIC
# MAGIC This guardrail:
# MAGIC 1. Translates OpenAI Chat Completions output format to extract code content
# MAGIC 2. Uses LlamaFirewall's CodeShield scanner to detect insecure code
# MAGIC 3. Translates the response back to Databricks Guardrails format
# MAGIC """
# MAGIC from typing import Any, Dict, List
# MAGIC import mlflow
# MAGIC from mlflow.models import set_model
# MAGIC import pandas as pd
# MAGIC import os
# MAGIC
# MAGIC class LlamaFirewallOutputModel(mlflow.pyfunc.PythonModel):
# MAGIC     def __init__(self):
# MAGIC         self.firewall = None
# MAGIC
# MAGIC     def load_context(self, context):
# MAGIC         """Initialize LlamaFirewall with CodeShield scanner for assistant outputs."""
# MAGIC         from llamafirewall import LlamaFirewall, Role, ScannerType
# MAGIC
# MAGIC         self.firewall = LlamaFirewall(
# MAGIC             scanners={
# MAGIC                 Role.ASSISTANT: [ScannerType.CODE_SHIELD],
# MAGIC             }
# MAGIC         )
# MAGIC
# MAGIC     def _invoke_guardrail(self, code_content: str) -> Dict[str, Any]:
# MAGIC         """
# MAGIC         Invokes LlamaFirewall's CodeShield scanner to detect insecure code.
# MAGIC
# MAGIC         Returns:
# MAGIC             Dict with scan results
# MAGIC         """
# MAGIC         from llamafirewall import AssistantMessage
# MAGIC
# MAGIC         result = self.firewall.scan(AssistantMessage(content=code_content))
# MAGIC
# MAGIC         flagged = result.action.value != "allow"
# MAGIC
# MAGIC         return {
# MAGIC             "is_insecure": flagged,
# MAGIC             "action": result.action.value,
# MAGIC             "reason": result.reason if result.reason else None,
# MAGIC             "scanner": "CodeShield"
# MAGIC         }
# MAGIC
# MAGIC     def _translate_output_guardrail_request(self, request: dict) -> str:
# MAGIC         """
# MAGIC         Translates an OpenAI Chat Completions (ChatV1) response to extract code content.
# MAGIC         """
# MAGIC         if (request["mode"]["phase"] != "output") or (request["mode"]["stream_mode"] is None) or (request["mode"]["stream_mode"] == "streaming"):
# MAGIC             raise Exception(f"Invalid mode: {request}.")
# MAGIC         if ("choices" not in request):
# MAGIC             raise Exception(f"Missing key \"choices\" in request: {request}.")
# MAGIC
# MAGIC         choices = request["choices"]
# MAGIC         code_content = ""
# MAGIC
# MAGIC         for choice in choices:
# MAGIC             if ("message" not in choice):
# MAGIC                 raise Exception(f"Missing key \"message\" in \"choices\": {request}.")
# MAGIC             if ("content" not in choice["message"]):
# MAGIC                 raise Exception(f"Missing key \"content\" in \"choices[\"message\"]\": {request}.")
# MAGIC             code_content += choice["message"]["content"]
# MAGIC
# MAGIC         return code_content
# MAGIC
# MAGIC     def _translate_guardrail_response(self, scan_result: Dict[str, Any], original_content: str) -> Dict[str, Any]:
# MAGIC         """
# MAGIC         Translates LlamaFirewall CodeShield scan results to the Databricks Guardrails format.
# MAGIC         """
# MAGIC         if scan_result["is_insecure"]:
# MAGIC             if scan_result["action"] == "block":
# MAGIC                 return {
# MAGIC                     "decision": "reject",
# MAGIC                     "reject_message": (
# MAGIC                         f"🚫🚫🚫 The generated code has been flagged as insecure by LlamaFirewall (CodeShield). 🚫🚫🚫\n"
# MAGIC                         f"Reason: {scan_result['reason']}"
# MAGIC                     )
# MAGIC                 }
# MAGIC             else:
# MAGIC                 warning_message = "⚠️⚠️⚠️ WARNING: The generated code has been flagged as having potential security issues by LlamaFirewall (CodeShield). Please review carefully before use. ⚠️⚠️⚠️"
# MAGIC                 return {
# MAGIC                     "decision": "sanitize",
# MAGIC                     "guardrail_response": {"include_in_response": True, "response": warning_message, "scan_result": scan_result},
# MAGIC                     "sanitized_input": {
# MAGIC                         "choices": [{
# MAGIC                             "message": {
# MAGIC                                 "role": "assistant",
# MAGIC                                 "content": original_content
# MAGIC                             }
# MAGIC                         }]
# MAGIC                     }
# MAGIC                 }
# MAGIC
# MAGIC         return {
# MAGIC             "decision": "proceed",
# MAGIC             "guardrail_response": {"include_in_response": True, "response": scan_result}
# MAGIC         }
# MAGIC
# MAGIC     def predict(self, context, model_input, params=None):
# MAGIC         """
# MAGIC         Applies the Code Shield guardrail to the model output and returns the guardrail response.
# MAGIC         """
# MAGIC         if isinstance(model_input, pd.DataFrame):
# MAGIC             model_input = model_input.to_dict("records")
# MAGIC             model_input = model_input[0]
# MAGIC             if not isinstance(model_input, dict):
# MAGIC                 return {"decision": "reject", "reject_reason": f"Couldn't parse model input: {model_input}"}
# MAGIC         elif not isinstance(model_input, dict):
# MAGIC             return {"decision": "reject", "reject_reason": f"Couldn't parse model input: {model_input}"}
# MAGIC
# MAGIC         try:
# MAGIC             code_content = self._translate_output_guardrail_request(model_input)
# MAGIC             scan_result = self._invoke_guardrail(code_content)
# MAGIC             result = self._translate_guardrail_response(scan_result, code_content)
# MAGIC             return result
# MAGIC         except Exception as e:
# MAGIC             error_message = str(e)
# MAGIC             return {"decision": "reject", "reject_reason": f"Errored with the following error message: {error_message}"}
# MAGIC
# MAGIC set_model(LlamaFirewallOutputModel())

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 3: Log the model to MLflow and register it to UC

# COMMAND ----------

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
            "llamafirewall"
        ]
    )

print(f"✅ Model logged to: {model_info.model_uri}")
print(f"✅ Model registered as: {registered_model_path}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 4: Test the model
# MAGIC Test the model with various inputs to ensure that it's working correctly.
# MAGIC
# MAGIC These are the same test cases used in the standalone Code Shield deployment for comparison.

# COMMAND ----------

# Load the model
loaded_model = mlflow.pyfunc.load_model(model_info.model_uri)

print("Testing weak hash (MD5) content...")
response = loaded_model.predict(model_input_example)
print(f"Weak hash response: {response}")
assert "decision" in response

print("\nTesting insecure C code (buffer overflow)...")
insecure_content = {
  "choices": [
      {
        "index": 0,
        "message": {
            "role": "assistant",
             "content": """void vulnerable_function(char *user_input) {
              char buffer[50];
              strcpy(buffer, user_input);  // Not checking about length
              printf("User input: %s\\n", buffer);
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

print("\nTesting safe code...")
safe_content = {
  "choices": [
      {
        "index": 0,
        "message": {
            "role": "assistant",
            "content": "def greet(name: str) -> str:\n    return f'Hello, {name}!'",
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

response = loaded_model.predict(safe_content)
print(f"Safe code response: {response}")
assert "decision" in response
assert response["decision"] == "proceed", "Safe code should proceed"

print("\n✅ All validation tests completed!")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 5: Deploy to Model Serving

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
# MAGIC Navigate to the AI Gateway settings for your foundation model endpoint and add this
# MAGIC serving endpoint as a custom **output** guardrail. The process is identical to adding
# MAGIC the standalone Code Shield endpoint.
# MAGIC
# MAGIC ## Step 8: Use your foundation model for inference
# MAGIC
# MAGIC Responses containing insecure generated code will be blocked or flagged by
# MAGIC LlamaFirewall's CodeShield scanner before reaching the user.

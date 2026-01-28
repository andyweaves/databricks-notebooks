from databricks.sdk import WorkspaceClient
import os
import json
import pathlib
import pandas as pd

def check_or_set_env_var(var_name: str, var_value: str):
    """
    Checks if the environment variable `var_name` is set to `var_value`.
    If it is not, it sets it to `var_value`.
    """
    if var_name in os.environ:
        if os.environ[var_name] != var_value:
            os.environ[var_name] = var_value
    else:
        os.environ[var_name] = var_value

def create_config(workspace_client: WorkspaceClient, model_name: str, skip_codes: list, output_dir: str):

  pathlib.Path(output_dir).mkdir(exist_ok=True) 

  #https://reference.garak.ai/en/latest/garak.generators.rest.html

  req_template = {
    "messages": [
        {
          "role": "user",
          "content": "$INPUT"
        }
    ],
    "max_tokens": 1024
  }

  rest_json = {
    "rest": {
        "RestGenerator": {
          "name": f"{os.environ['MODEL_NAME']}",
          "uri": f"{os.environ['ENDPOINT_URL']}",
          "method": "post",
          "headers": {
              "Authorization": f"Bearer $KEY",
              "Content-Type": "application/json"
          },
          "req_template_json_object": req_template,
          "response_json": True,
          "response_json_field": "$.choices[0].message.content",
          "ratelimit_codes": [429],
          "skip_codes": skip_codes
        }
    }
  }
  json.dump(rest_json, open(f"{output_dir}/{model_name}.json", "w"))
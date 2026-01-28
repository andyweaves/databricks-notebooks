# Databricks notebook source
# MAGIC %md
# MAGIC # Scan your model using [BlackIce](https://www.databricks.com/blog/announcing-blackice-containerized-red-teaming-toolkit-ai-security-testing)
# MAGIC
# MAGIC ## About BlackIce
# MAGIC [BlackIce](https://github.com/databricks/containers/tree/release-17.3-LTS/ubuntu/blackice) is an open-source containerized toolkit designed for red teaming AI models, including Large Language Models (LLMs) and classical machine learning (ML) models. Inspired by the convenience and standardization of Kali Linux in traditional penetration testing, BlackIce simplifies AI security assessments by providing a reproducible container image preconfigured with specialized evaluation tools.
# MAGIC
# MAGIC >#### ⚠️⚠️ **Important!** ⚠️⚠️
# MAGIC >
# MAGIC > You will need: 
# MAGIC > - **A DBR 17.3-LTS cluster** with the `databricksruntime/blackice:17.3-LTS` container running via [Databricks Container Services](https://docs.databricks.com/aws/en/compute/custom-containers)

# COMMAND ----------

# DBTITLE 1,Cell 2
from utils.databricks import get_workspace_client, get_serving_endpoints
import os

ws = get_workspace_client(
  # Please note - the below is not best practice, but unfortunately unified auth isn't supported on DCS
  host=dbutils.notebook.entry_point.getDbutils().notebook().getContext().apiUrl().get(), 
  token=dbutils.notebook.entry_point.getDbutils().notebook().getContext().apiToken().get())

serving_endpoints = [se.name for se in get_serving_endpoints(workspace_client=ws)]
dbutils.widgets.dropdown("target_model", defaultValue=serving_endpoints[0], choices=serving_endpoints[:1000], label="Target Model")
dbutils.widgets.text("output_dir", defaultValue=f"{os.getcwd()}", label="Output Directory")

output_dir = dbutils.widgets.get("output_dir")
target_model = dbutils.widgets.get("target_model")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Scan with Garak
# MAGIC
# MAGIC ### About Garak
# MAGIC `garak` checks if an LLM can be made to fail in a way we don't want. `garak` probes for hallucination, data leakage, prompt injection, misinformation, toxicity generation, jailbreaks, and many other weaknesses. If you know `nmap` or `msf` / Metasploit Framework, `garak` does somewhat similar things to them, but for LLMs.
# MAGIC
# MAGIC For more information please see the [docs](https://docs.garak.ai/garak) and [Github](https://github.com/NVIDIA/garak) repo

# COMMAND ----------

# MAGIC %sh garak --list_probes

# COMMAND ----------

# MAGIC %md
# MAGIC #### ⚠️⚠️ **Important!** ⚠️⚠️
# MAGIC >
# MAGIC > `skip_codes = [400]`: 
# MAGIC > - If we have Guardrails configured, they will return a `400 BAD REQUEST` error when they fail
# MAGIC > - `garak` will see this as a connection failure and stop running, so we need to tell it to skip these responses
# MAGIC > - We'll still be able to see the overall results of our testing via the inference table logs

# COMMAND ----------

from utils.garak import create_config, check_or_set_env_var
import os
import subprocess

check_or_set_env_var("MODEL_NAME", target_model)
check_or_set_env_var("ENDPOINT_URL", f"{ws.config.host}/serving-endpoints/{target_model}/invocations")
check_or_set_env_var("REST_API_KEY", ws.config.token)
check_or_set_env_var("XDG_DATA_HOME", output_dir)

skip_codes = [400] # If you don't have guardrails configured remove this - With this Garak will see the 400 bad request error returned by Guardrails as a failure and fail all requests

create_config(workspace_client=ws, model_name=target_model, skip_codes=skip_codes, output_dir=f"{output_dir}/garak")
subprocess.run(["garak", "--model_type", "rest", "-G", f"garak/{target_model}.json", "--report_prefix", target_model, "--probes", "dan.DanInTheWild"])

# COMMAND ----------

# MAGIC %md
# MAGIC ### Review the Garak report
# MAGIC
# MAGIC >#### ⚠️⚠️ **Important** ⚠️⚠️
# MAGIC > - As mentioned above, having guardrails configured will return a `400 BAD REQUEST` error which we need to tell `garak` to skip
# MAGIC > - This will skew our results, so we'll mainly look at the `hitlog` (essentially attacks that successfully bypassed our guardrails)
# MAGIC > - As mentioned above, we'll still be able to see the overall results of our testing via the inference table logs

# COMMAND ----------

from pyspark.sql.functions import col

hitlog = (
  spark.read.json(f"file:///{output_dir}/garak/garak_runs/{target_model}.hitlog.jsonl")
    .select(
      "probe",
      "detector",
      "goal",
      col("prompt.turns").alias("prompt"),
      col("output.text").alias("response"),
    )
  )
display(hitlog)

# COMMAND ----------

# MAGIC %md
# MAGIC ### Query the inference table
# MAGIC
# MAGIC >#### ⚠️⚠️ **Important** ⚠️⚠️
# MAGIC > - As mentioned above, we can see the real impact of our guardrails via our inference table logs
# MAGIC > - These will show which attempts are getting successfully blocked by our guardrails

# COMMAND ----------

# DBTITLE 1,Cell 8
inference_table_config = ws.serving_endpoints.get(target_model).ai_gateway.inference_table_config
inference_table = f"`{inference_table_config.catalog_name}`.`{inference_table_config.schema_name}`.`{inference_table_config.table_name_prefix}_payload`"

response_codes = (
  sql(f"""
      SELECT 
      request_date,
      status_code,
      COUNT(*) AS total_responses
      FROM {inference_table}
      WHERE request_date = CURRENT_DATE()
      GROUP BY ALL
      ORDER BY request_date DESC;
      """))
display(response_codes)

responses = (
  sql(f"""
      SELECT 
      request_time, 
      request_date,
      requester,
      parse_json(request) AS request,
      parse_json(response) AS response,
      status_code
      FROM {inference_table}
      WHERE status_code = 400
      AND contains(response:message, 'Your request has been flagged by AI guardrails')
      ORDER BY request_time DESC;
      """))
display(responses)

responses_agg = (
  sql(f"""
      SELECT
      request_date,
      COALESCE(
        NULLIF(REGEXP_EXTRACT(response:message, "'label':\\\\s*'([^']+)'", 1), ''),
        NULLIF(REGEXP_EXTRACT(response:message, "Detected categories:\\\\s*(.+)", 1), '')
      ) AS extracted_label,
      COUNT(*) AS total_responses
      FROM {inference_table}
      WHERE status_code != 200
      AND request_date = CURRENT_DATE()
      GROUP BY request_date, extracted_label
      ORDER BY request_date DESC;
      """).na.drop())
display(responses_agg)

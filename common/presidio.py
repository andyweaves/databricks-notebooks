# Databricks notebook source
# MAGIC %pip install -q -r ../../requirements.txt

# COMMAND ----------

dbutils.library.restartPython()

# COMMAND ----------

# MAGIC %sh
# MAGIC python -m spacy download en_core_web_lg > /databricks/driver/logs/spacy.log

# Databricks notebook source
# MAGIC %md
# MAGIC ### Confirm that PrivateLink and connections back to the Control Plane are working

# COMMAND ----------

# MAGIC %sh
# MAGIC nslookup london.cloud.databricks.com

# COMMAND ----------

# MAGIC %sh
# MAGIC curl -v -L https://london.cloud.databricks.com

# COMMAND ----------

# MAGIC %sh
# MAGIC nslookup tunnel.eu-west-2.cloud.databricks.com

# COMMAND ----------

# MAGIC %sh
# MAGIC nc -zv mdio2468d9025m.c6fvhwk6cqca.eu-west-2.rds.amazonaws.com 3306

# COMMAND ----------

# MAGIC %md
# MAGIC ### Confirm that the Firewall is working

# COMMAND ----------

# MAGIC %sh
# MAGIC curl -v --max-time 10 https://www.databricks.com

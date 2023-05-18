# Databricks notebook source
# MAGIC %sql
# MAGIC SHOW TABLES IN diz.information_schema

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT 
# MAGIC t.table_catalog, t.table_schema, t.table_name, t.table_owner, p.grantor, p.grantee, p.privilege_type, p.inherited_from
# MAGIC FROM diz.information_schema.tables t LEFT JOIN diz.information_schema.table_privileges p ON t.table_catalog = p.table_catalog AND t.table_schema = p.table_schema AND t.table_name = p.table_name
# MAGIC WHERE comment = "contains_pii"

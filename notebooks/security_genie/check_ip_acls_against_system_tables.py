# Databricks notebook source
dbutils.widgets.text("catalog", "main")
dbutils.widgets.text("schema", "default")

# COMMAND ----------

sql(f"USE CATALOG {dbutils.widgets.get('catalog')}")
sql(f"USE SCHEMA {dbutils.widgets.get('schema')}")

# COMMAND ----------

# MAGIC %sql 
# MAGIC create or replace function ipv4_to_long(ip string)
# MAGIC returns long
# MAGIC return
# MAGIC   case
# MAGIC     when regexp_count(ip, "\\d+\\.\\d+\\.\\d+\\.\\d+") <> 1 then null
# MAGIC     else 
# MAGIC       mod(bigint(split(regexp_extract(ip, "\\d+\\.\\d+\\.\\d+\\.\\d+", 0), "\\.")[3]), 256) +
# MAGIC       mod(bigint(split(regexp_extract(ip, "\\d+\\.\\d+\\.\\d+\\.\\d+", 0), "\\.")[2]), 256) * 256 +
# MAGIC       mod(bigint(split(regexp_extract(ip, "\\d+\\.\\d+\\.\\d+\\.\\d+", 0), "\\.")[1]), 256) * 65536 +
# MAGIC       mod(bigint(split(regexp_extract(ip, "\\d+\\.\\d+\\.\\d+\\.\\d+", 0), "\\.")[0]), 256) * 16777216
# MAGIC   end;

# COMMAND ----------

# MAGIC %sql 
# MAGIC create or replace function ipv4_cidr_to_range(cidr string)
# MAGIC returns array<long>
# MAGIC return array(ipv4_to_long(split(cidr, "/")[0]), ipv4_to_long(split(cidr, "/")[0]) + power(2, 32-int(split(cidr, "/")[1]))-1)

# COMMAND ----------

from databricks.sdk import WorkspaceClient
from pyspark.sql.functions import explode, expr

# this only gets IP ACLs for the current workspace...
ws = WorkspaceClient()
ws_ips = [ip_acl for ip_acl in ws.ip_access_lists.list() if ip_acl.enabled and ip_acl.list_type.value == "ALLOW"]

data = [(ip_acl.label, ip_acl.ip_addresses) for ip_acl in ws_ips]
data.append( # add private IPs to filter out internal traffic
    ("private IPs", list(["192.168.0.0/16", "10.0.0.0/8", "72.16.0.0/12"]))
)

dataset = (spark.createDataFrame(data, ["name", "cidrs"])
           .select("name", explode("cidrs").alias("cidr"), expr("ipv4_cidr_to_range(cidr)").alias("cird_range")))

# COMMAND ----------

display(dataset)

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE TABLE good_ips_list (
# MAGIC   name STRING,
# MAGIC   cidr STRING,
# MAGIC   cidr_range ARRAY<BIGINT>
# MAGIC )

# COMMAND ----------

dataset.write.mode("overwrite").insertInto("good_ips_list")

# COMMAND ----------

# MAGIC %sql
# MAGIC DESCRIBE TABLE good_ips_list

# COMMAND ----------

# MAGIC %sql
# MAGIC
# MAGIC select * from good_ips_list

# COMMAND ----------

# DBTITLE 1,IPs Blocked By Account or Workspace IP ACLs
# MAGIC %sql
# MAGIC select source_ip_address, action_name, user_identity, workspace_id, event_date, count(*) from system.access.audit
# MAGIC where action_name in ('IpAccessDenied', 'accountIpAclsValidationFailed')
# MAGIC and event_date >= current_date() - interval 1 week
# MAGIC group by all
# MAGIC order by 5 desc,6 desc

# COMMAND ----------

# DBTITLE 1,Requests Coming from IPs Outside The IP ACLs Range
# MAGIC %sql
# MAGIC
# MAGIC select source_ip_address, action_name, user_identity, workspace_id, event_date, count(*) from system.access.audit
# MAGIC left anti join good_ips_list on ipv4_to_long(source_ip_address) between cidr_range[0] and cidr_range[1]
# MAGIC where source_ip_address is not null
# MAGIC and source_ip_address not in ('127.0.0.1', '0.0.0.0', '0:0:0:0:0:0:0:1%0', '')
# MAGIC and action_name not in ('IpAccessDenied', 'accountIpAclsValidationFailed')
# MAGIC and event_date >= current_date() - interval 1 week
# MAGIC group by all
# MAGIC order by 5 desc,6 desc

# COMMAND ----------

# MAGIC %sql
# MAGIC
# MAGIC CREATE OR REPLACE FUNCTION auth_attempts_outside_perimeter(include_events BOOLEAN DEFAULT FALSE)
# MAGIC   RETURNS TABLE
# MAGIC   LANGUAGE SQL
# MAGIC   NOT DETERMINISTIC
# MAGIC   RETURN SELECT event_date, user_identity, source_ip_address, action_name, user_agent, count(1) AS attempts, count(1) FILTER (WHERE response.status_code = 200) successful_attempts,
# MAGIC           CASE
# MAGIC             WHEN include_events THEN array_sort(
# MAGIC               collect_set(
# MAGIC                 named_struct(
# MAGIC                   'event_time',
# MAGIC                   event_time,
# MAGIC                   'user_agent',
# MAGIC                   user_agent,
# MAGIC                   'audit_level',
# MAGIC                   audit_level,
# MAGIC                   'workspace_id',
# MAGIC                   workspace_id,
# MAGIC                   'service_name',
# MAGIC                   service_name,
# MAGIC                   'action_name',
# MAGIC                   action_name,
# MAGIC                   'error_message',
# MAGIC                   response.error_message,
# MAGIC                   'status_code',
# MAGIC                   response.status_code,
# MAGIC                   'additional_info',
# MAGIC                   NULL
# MAGIC                 )
# MAGIC               ),
# MAGIC               (left, right) -> CASE
# MAGIC                 WHEN left.event_time > right.event_time THEN -1
# MAGIC                 WHEN left.event_time < right.event_time THEN 1
# MAGIC                 ELSE 0
# MAGIC               END
# MAGIC             )
# MAGIC           END AS events
# MAGIC           FROM system.access.audit
# MAGIC           LEFT ANTI JOIN good_ips_list
# MAGIC             ON ipv4_to_long(source_ip_address) BETWEEN cidr_range[0] and cidr_range[1]
# MAGIC           WHERE source_ip_address IS NOT NULL
# MAGIC           AND source_ip_address NOT IN ('127.0.0.1', '0.0.0.0', '0:0:0:0:0:0:0:1%0', '')
# MAGIC           AND (action_name IN ('oidcTokenAuthorization') OR action_name LIKE '%login')
# MAGIC           GROUP BY ALL;

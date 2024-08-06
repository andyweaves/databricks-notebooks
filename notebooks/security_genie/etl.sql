-- Databricks notebook source
CREATE OR REFRESH MATERIALIZED VIEW audit (
  event_time TIMESTAMP NOT NULL COMMENT 'A timestamp in `yyyy-MM-ddTHH:mm:ss.SSS+00:00` format representing the time that the audit event was generated', 
  event_date DATE NOT NULL COMMENT 'A date in `yyyy-MM-dd` format representing date that the audit event was generated',
  account_id STRING NOT NULL COMMENT 'The Databricks account id for the account that the audit event was generated in',
  workspace_id STRING NOT NULL COMMENT 'The Databricks workspace id for the workspace that generated the audit event. Events with a workspace_id of 0 are account level events',
  audit_level STRING NOT NULL COMMENT 'A string containing either `ACCOUNT_LEVEL` or `WORKSPACE_LEVEL` to indicate whether the event was generated by an account or workspace level action',
  source_ip_address STRING COMMENT 'The IP address from which the request originated. Note that sometimes IP addresses within this field also contain the port, I.e. `:0`. Invalid IPs are null, blank strings, `127.0.0.1`, and `0.0.0.0`',
  user_identity STRUCT<email STRING, subject_name STRING> COMMENT 'A struct, the most important field of which is the email, accessible via `user_identity.email`. This is the email address of the Databricks user whose action generated the audit event',
  user_agent STRING COMMENT 'The HTTP user agent used to make the request',
  service_name STRING NOT NULL COMMENT 'The Databricks service name that the audit event is related to',
  action_name STRING NOT NULL COMMENT 'The Databricks action name that the audit event is related to',
  request_params MAP<STRING, STRING> COMMENT 'A map containing key value pairs associated with the request that generated the audit event',
  response STRUCT<status_code INT, error_message STRING, result STRING> NOT NULL COMMENT 'A struct, typically containing 3 fields of interest: 1) `response.status_code` - an HTTP status code such as 200 or 403. 2) `response.error_message` - any error messages generated by the audit event. 3) `response.result` - a JSON string containing additional detail about the result of the audit event'
) AS (
SELECT 
event_time,
event_date,
account_id,
workspace_id,
audit_level,
source_ip_address,
user_identity,
user_agent,
service_name,
action_name,
request_params,
response
FROM system.access.audit
WHERE event_date >= current_date() - INTERVAL 90 DAYS
)

-- COMMAND ----------

-- MAGIC %environment
-- MAGIC "client": "1"
-- MAGIC "base_environment": ""

-- Databricks notebook source
CREATE WIDGET text catalog DEFAULT 'main';
CREATE WIDGET text schema DEFAULT 'default';
--CREATE CATALOG IF NOT EXISTS IDENTIFIER(:catalog);
CREATE SCHEMA IF NOT EXISTS IDENTIFIER(:schema);
USE CATALOG ${catalog};
USE SCHEMA IDENTIFIER(:schema)

-- COMMAND ----------

USE CATALOG ${catalog};
USE SCHEMA IDENTIFIER(:schema)

-- COMMAND ----------

CREATE
OR REPLACE FUNCTION failed_authentication_attempts()
RETURNS TABLE
COMMENT 'Can be used to detect repeated failed authentication attempts, which could indicate an attacker trying to brute force access to your account. The results are limited to the last 90 days.'
RETURN
  SELECT
  event_date,
  'AUTHN_FAILED' AS event_type,
  ifnull(user_identity.email, request_params.user) AS username,
  count(*) AS total_failed_attempts,
  count(distinct workspace_id) AS number_of_different_workspaces,
  count(distinct source_ip_address) AS number_of_different_ips,
  count_if(audit_level = 'ACCOUNT_LEVEL') AS number_of_account_level_failures,
  count_if(audit_level = 'WORKSPACE_LEVEL') AS number_of_workspace_level_failures,
  count(distinct service_name) AS number_of_different_services,
  array_sort(collect_set(named_struct(
      'event_time', event_time,
      'source_ip_address', source_ip_address,
      'user_agent', user_agent,
      'audit_level', audit_level,
      'workspace_id', workspace_id,
      'service_name', service_name,
      'action_name', action_name,
      'error_message', response.error_message,
      'status_code', response.status_code
      )), (left, right) -> CASE WHEN left.event_time > right.event_time THEN -1 WHEN left.event_time < right.event_time THEN 1 ELSE 0 END)
   AS failed_attempts
  FROM audit_logs 
  WHERE (contains(lower(action_name), 'login') OR contains(lower(action_name), 'auth'))  
  AND response.status_code = 401
  --AND event_date >= (SELECT MAX(event_date) FROM audit_logs) - INTERVAL 90 DAYS
  GROUP BY ALL
  ORDER BY event_date DESC, total_failed_attempts DESC

-- COMMAND ----------

SELECT MAX(event_date) FROM audit_logs - INTERVAL 90 DAYS

-- COMMAND ----------

CREATE
OR REPLACE FUNCTION failed_ip_access_attempts()
RETURNS TABLE
COMMENT 'Can be used to detect repeated failed IP access list attempts, which indicates that someone is trying to access your account from an untrusted IP address range. The results are limited to the last 90 days.'
RETURN
   SELECT
  event_date,
  'IP_ACCESS_FAILED' AS event_type,
  source_ip_address,
  count(*) AS total_failed_attempts,
  count(distinct workspace_id) AS number_of_different_workspaces,
  count(distinct ifnull(user_identity.email, request_params.user)) AS number_of_different_users,
  count_if(audit_level = 'ACCOUNT_LEVEL') AS number_of_account_level_failures,
  count_if(audit_level = 'WORKSPACE_LEVEL') AS number_of_workspace_level_failures,
  count(distinct service_name) AS number_of_different_services,
  array_sort(collect_set(named_struct(
      'event_time', event_time,
      'username', ifnull(user_identity.email, request_params.user),
      'user_agent', user_agent,
      'audit_level', audit_level,
      'workspace_id', workspace_id,
      'service_name', service_name,
      'action_name', action_name,
      'error_message', response.error_message,
      'status_code', response.status_code
      )), (left, right) -> CASE WHEN left.event_time > right.event_time THEN -1 WHEN left.event_time < right.event_time THEN 1 ELSE 0 END)
   AS failed_attempts
  FROM audit_logs 
  WHERE action_name IN ('IpAccessDenied', 'accountIpAclsValidationFailed') 
  --AND event_date >= (SELECT MAX(event_date) FROM audit_logs - INTERVAL 90 DAYS) 
  GROUP BY ALL
  ORDER BY event_date DESC, total_failed_attempts DESC

-- COMMAND ----------

CREATE
OR REPLACE FUNCTION failed_authorisation_attempts()
RETURNS TABLE
COMMENT 'Can be used to detect repeated failed authorisation attempts, which could indicate attempts at lateral movement and/or privilege escalation. Note that failed IP ACL attempts are not included in this list. Use the function failed_ip_access_attempts() to investigate these instead. The results are limited to the last 90 days.'
RETURN
  SELECT
  event_date,
  'AUTHZ_FAILED' AS event_type,
  ifnull(user_identity.email, request_params.user) AS username,
  count(*) AS total_failed_attempts,
  count(distinct workspace_id) AS number_of_different_workspaces,
  count(distinct source_ip_address) AS number_of_different_ips,
  count_if(audit_level = 'ACCOUNT_LEVEL') AS number_of_account_level_failures,
  count_if(audit_level = 'WORKSPACE_LEVEL') AS number_of_workspace_level_failures,
  count(distinct service_name) AS number_of_different_services,
  count(distinct action_name) AS number_of_different_actions,
  array_sort(collect_set(named_struct(
      'event_time', event_time,
      'source_ip_address', source_ip_address,
      'user_agent', user_agent,
      'audit_level', audit_level,
      'workspace_id', workspace_id,
      'service_name', service_name,
      'action_name', action_name,
      'error_message', response.error_message,
      'status_code', response.status_code
      )), (left, right) -> CASE WHEN left.event_time > right.event_time THEN -1 WHEN left.event_time < right.event_time THEN 1 ELSE 0 END)
   AS failed_attempts
  FROM audit_logs 
  WHERE action_name NOT IN ('IpAccessDenied', 'accountIpAclsValidationFailed')  
  AND response.status_code = 403
  --AND event_date >= (SELECT MAX(event_date) FROM audit_logs) - INTERVAL 90 DAYS
  GROUP BY ALL
  ORDER BY event_date DESC, total_failed_attempts DESC

-- COMMAND ----------

SELECT * FROM failed_authentication_attempts()

-- COMMAND ----------

SELECT * FROM failed_authorisation_attempts()

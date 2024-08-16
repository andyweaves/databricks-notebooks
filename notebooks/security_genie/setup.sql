-- Databricks notebook source
CREATE WIDGET text catalog DEFAULT 'main';
CREATE WIDGET text schema DEFAULT 'default';
--CREATE CATALOG IF NOT EXISTS IDENTIFIER(:catalog);
CREATE SCHEMA IF NOT EXISTS IDENTIFIER(:schema);
USE CATALOG ${catalog};
USE SCHEMA IDENTIFIER(:schema)

-- COMMAND ----------

CREATE
OR REPLACE FUNCTION failed_authentication_attempts()
RETURNS TABLE
COMMENT 'Can be used to detect repeated failed authentication attempts, which could indicate an attacker trying to brute force access to your account'
RETURN
  SELECT
  event_date,
  ifnull(user_identity.email, request_params.user) AS username,
  count(distinct source_ip_address) AS number_of_different_ips,
  count(distinct service_name) AS number_of_different_services,
  count(distinct user_agent) AS number_of_different_user_agents,
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
   AS failed_attempts,
  count(*) AS total_failed_attempts 
  FROM audit_logs 
  WHERE (contains(lower(action_name), 'login') OR contains(lower(action_name), 'auth'))  
  AND response.status_code = 401
  GROUP BY ALL
  ORDER BY event_date DESC, total_failed_attempts DESC

-- COMMAND ----------

CREATE
OR REPLACE FUNCTION failed_ip_access_attempts()
RETURNS TABLE
COMMENT 'Can be used to detect repeated failed IP access list attempts, which indicates that someone is trying to access your account from an untrusted IP address range'
RETURN
   SELECT
  event_date,
  source_ip_address,
  count(distinct ifnull(user_identity.email, request_params.user)) AS number_of_different_users,
  count(distinct service_name) AS number_of_different_services,
  count(distinct user_agent) AS number_of_different_user_agents,
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
   AS failed_attempts,
  count(*) AS total_failed_attempts
  FROM audit_logs 
  WHERE action_name IN ('IpAccessDenied', 'accountIpAclsValidationFailed')  
  GROUP BY ALL
  ORDER BY event_date DESC, total_failed_attempts DESC

-- COMMAND ----------

SELECT * FROM failed_ip_access_attempts()

-- COMMAND ----------

SELECT * FROM failed_authentication_attempts()

-- COMMAND ----------

SELECT 
service_name,
action_name,
count(*) AS total
FROM `system`.access.audit WHERE response.status_code = 403
GROUP BY ALL
ORDER BY TOTAL DESC

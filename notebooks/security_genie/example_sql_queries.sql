-- Databricks notebook source
-- MAGIC %md
-- MAGIC ### What security best practices should I follow for Databricks?

-- COMMAND ----------

SELECT
  id,
  check_id,
  category,
  check,
  severity,
  recommendation,
  doc_url,
  logic,
  api
FROM
  arunuc.security_analysis.security_best_practices
ORDER BY
  id ASC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### How do my workspaces compare against security best practices?

-- COMMAND ----------

SELECT
  sc.workspaceid,
  sbp.severity,
  sbp.check_id,
  sbp.category,
  check,
  CASE
    WHEN sc.score = 0 THEN TRUE
    WHEN sc.score = 1 THEN FALSE
    ELSE NULL
  END AS is_implemented,
  sbp.recommendation,
  sbp.doc_url,
  sc.additional_details
FROM
  arunuc.security_analysis.security_checks sc
  LEFT JOIN arunuc.security_analysis.security_best_practices sbp ON sc.id = sbp.id
ORDER BY
  sbp.severity ASC,
  sc.workspaceid DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### What is the security posture of my Databricks account or workspaces? How secure is my Databricks account? Which security best practices should I implement?

-- COMMAND ----------

SELECT
  sc.workspaceid,
  sbp.severity,
  sbp.check_id,
  sbp.category,
  check,
  sbp.recommendation,
  sbp.doc_url,
  sc.additional_details
FROM
  arunuc.security_analysis.security_checks sc
  LEFT JOIN arunuc.security_analysis.security_best_practices sbp ON sc.id = sbp.id
WHERE
  sc.score = 1
ORDER BY
  sbp.severity ASC,
  sc.workspaceid DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Has anyone from Databricks logged into my workspaces recently?

-- COMMAND ----------

SELECT
  event_date,
  event_time,
  source_ip_address,
  workspace_id,
  request_params.user,
  request_params.duration,
  request_params.reason,
  response.status_code
FROM
  system.access.audit
WHERE
  action_name = 'databricksAccess'
  AND event_date >= (
    SELECT
      MAX(event_date)
    FROM
      system.access.audit
  ) - INTERVAL 90 DAYS
ORDER BY
  event_date DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Can anyone from Databricks login to my workspaces?

-- COMMAND ----------

SELECT
  event_date,
  event_time,
  workspace_id,
  user_identity.email,
  CASE
    WHEN request_params.workspaceConfValues = 'indefinite' THEN "No Expiration"
    WHEN cast(request_params.workspaceConfValues AS TIMESTAMP) < event_time THEN "Disabled Access"
    ELSE "Enabled Access for " || INT(
      round(
        cast(
          cast(
            request_params.workspaceConfValues AS TIMESTAMP
          ) - event_time AS INT
        ) / 3600
      )
    ) || " Hours"
  END AS set_configuration
FROM
  system.access.audit
WHERE
  action_name = 'workspaceConfEdit'
  AND request_params.workspaceConfKeys = 'customerApprovedWSLoginExpirationTime'
ORDER BY
  event_time DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### After login, has anyone tried to access my Databricks account or workspaces from an untrusted network recently?

-- COMMAND ----------

SELECT
  WINDOW(event_time, '60 minutes').start AS window_start,
  WINDOW(event_time, '60 minutes').
end AS window_end,
source_ip_address,
ifnull(user_identity.email, request_params.user) AS username,
workspace_id,
service_name,
action_name,
response.status_code,
response.error_message,
count(*) AS total_events
FROM
  system.access.audit
WHERE action_name IN (
      'IpAccessDenied',
      'accountIpAclsValidationFailed'
    )
  AND event_date >= (
    SELECT
      MAX(event_date)
    FROM
      system.access.audit
  ) - INTERVAL 90 DAYS
GROUP BY
  ALL
ORDER BY
  window_end DESC,
  total_events DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Has anyone tried to access my Delta Shares from an untrusted network recently?

-- COMMAND ----------

SELECT
  WINDOW(event_time, '60 minutes').start AS window_start,
  WINDOW(event_time, '60 minutes').end AS window_end,
  source_ip_address,
  request_params.recipient_name,
  request_params.recipient_id,
  request_params.recipient_authentication_type,
  request_params.metastore_id,
  request_params.workspace_id,
  request_params.user_agent,
  service_name,
  action_name,
  response.status_code,
  response.error_message,
  CASE WHEN isnotnull(any_value(request_params.share_name)) THEN collect_set(
    named_struct(
      'share_name', request_params.share_name,
      'share_id', request_params.share_id
      )
    ) ELSE NULL END AS shares_accessed,
  count(*) AS total_events
FROM
  system.access.audit
WHERE
  startswith(action_name, 'deltaSharing') AND
  request_params.is_ip_access_denied = 'true' AND
  event_date >= (
    SELECT
      MAX(event_date)
    FROM
      system.access.audit
  ) - INTERVAL 90 DAYS
GROUP BY ALL
ORDER BY
  window_end DESC,
  total_events DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Has anyone failed authentication to my Databricks account or workspaces recently?

-- COMMAND ----------

SELECT
  WINDOW(event_time, '60 minutes').start AS window_start, WINDOW(event_time, '60 minutes').end AS window_end,
  source_ip_address,
  ifnull(user_identity.email, request_params.user) AS username,
  workspace_id,
  service_name,
  action_name,
  response.status_code,
  response.error_message,
  count(*) AS total_events
FROM
  system.access.audit
WHERE
  (
    contains(lower(action_name), 'login')
    OR contains(lower(action_name), 'auth')
  )
  AND response.status_code = 401
  AND event_date >= (
    SELECT
      MAX(event_date)
    FROM
      system.access.audit
  ) - INTERVAL 999 DAYS
GROUP BY
  ALL
ORDER BY
  window_end DESC,
  total_events DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Has anyone failed authorization within my Databricks account or workspaces recently?

-- COMMAND ----------

SELECT WINDOW(event_time, '60 minutes').start AS window_start, WINDOW(event_time, '60 minutes').end AS window_end,
source_ip_address,
ifnull(user_identity.email, request_params.user) AS username,
workspace_id,
  service_name,
  action_name,
  response.status_code,
  collect_set(response.error_message) AS error_messages,
  count(*) AS total_events
FROM system.access.audit
WHERE
  action_name NOT IN (
    'IpAccessDenied',
    'accountIpAclsValidationFailed'
  )
  AND response.status_code = 403
  AND event_date >= (
    SELECT
      MAX(event_date)
    FROM
      system.access.audit
  ) - INTERVAL 90 DAYS
GROUP BY
  ALL
ORDER BY
  window_end DESC,
  total_events DESC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ### Has anyone tried to repeatedly access secrets within my Databricks workspaces recently?

-- COMMAND ----------

SELECT WINDOW(event_time, '60 minutes').start AS window_start, WINDOW(event_time, '60 minutes').end AS window_end,
source_ip_address,
ifnull(user_identity.email, request_params.user) AS username,
workspace_id,
  service_name,
  action_name,
  response.status_code,
  collect_set(concat('Scope: ', request_params.scope, ' Key: ', audit.request_params.key)) AS secrets_accessed,
  collect_set(response.error_message) AS error_messages,
  count(*) AS total_events
FROM system.access.audit
 WHERE
    action_name = 'getSecret'
    AND user_identity.email NOT IN ('System-User')
AND event_date >= (
    SELECT
      MAX(event_date)
    FROM
      system.access.audit
  ) - INTERVAL 90 DAYS
GROUP BY
  ALL
ORDER BY
  window_end DESC,
  total_events DESC

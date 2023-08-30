-- Databricks notebook source
-- MAGIC %md
-- MAGIC ## Create Temp Views

-- COMMAND ----------

CREATE
OR REPLACE TEMPORARY VIEW pii_tags AS (
  SELECT
    concat(catalog_name, '.', schema_name, '.', table_name) AS securable,
    'table' AS securable_type,
    sort_array(collect_set(tag_name)) AS tags
  FROM
    system.information_schema.table_tags
  GROUP BY
    1,
    2
  UNION ALL
  SELECT
    concat(catalog_name, '.', schema_name) AS securable,
    'schema' AS securable_type,
    sort_array(collect_set(tag_name)) AS tags
  FROM
    system.information_schema.schema_tags
  GROUP BY
    1,
    2
  UNION ALL
  SELECT
    concat(catalog_name) AS securable,
    'catalog' AS securable_type,
    sort_array(collect_set(tag_name)) AS tags
  FROM
    system.information_schema.catalog_tags
  GROUP BY
    1,
    2
  UNION ALL
  SELECT
    concat(catalog_name, '.', schema_name, '.', table_name) AS securable,
    'table' AS securable_type,
    sort_array(collect_set(tag_name)) AS tags
  FROM
    system.information_schema.column_tags
  GROUP BY
    1,
    2
)

-- COMMAND ----------

CREATE
OR REPLACE TEMPORARY VIEW privileges AS (
  SELECT
    concat(
      table_catalog,
      '.',
      table_schema,
      '.',
      table_name
    ) AS securable,
    'table' AS securable_type,
    grantee,
    privilege_type
  FROM
    system.information_schema.table_privileges
  UNION ALL
  SELECT
    concat(catalog_name, '.', schema_name) AS securable,
    'schema' AS securable_type,
    grantee,
    privilege_type
  FROM
    system.information_schema.schema_privileges
  UNION ALL
  SELECT
    catalog_name AS securable,
    'catalog' AS securable_type,
    grantee,
    privilege_type
  FROM
    system.information_schema.catalog_privileges
)

-- COMMAND ----------

CREATE
OR REPLACE TEMPORARY VIEW privileges_and_tags AS (
  SELECT
    t.securable,
    t.securable_type,
    p.grantee,
    p.privilege_type,
    t.tags
  FROM
    pii_tags t
    JOIN privileges p ON t.securable = p.securable
    AND t.securable_type = p.securable_type
  WHERE
    NOT (
      startswith(p.securable, '__databricks_internal.')
      OR contains(p.securable, 'information_schema')
    )
    AND array_contains(t.tags, 'pii')
)

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Which users have access to PII?

-- COMMAND ----------

SELECT * FROM privileges_and_tags ORDER BY securable ASC

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Most Privileged Users & Groups

-- COMMAND ----------

SELECT 
grantee AS group, 
privilege_type,
securable_type AS securable_with_pii,
count(*) AS total
FROM privileges_and_tags
GROUP BY 1, 2, 3
ORDER BY total DESC

# Databricks notebook source
# MAGIC %run ../common/generate_fake_pii

# COMMAND ----------

# MAGIC %sql
# MAGIC USE CATALOG diz

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE SCHEMA IF NOT EXISTS raw;
# MAGIC CREATE SCHEMA IF NOT EXISTS processed

# COMMAND ----------

df = generate_fake_pii_data(num_rows=1000).select("customer_id", "email", "phone_number", "postcode", "date_of_birth", "ipv4")
display(df)

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE VIEW vw_customer_data_redacted 
# MAGIC AS
# MAGIC SELECT
# MAGIC   customer_id,
# MAGIC   CASE WHEN
# MAGIC     is_member('pii_viewer') THEN email
# MAGIC     ELSE regexp_extract(email, '^.*@(.*)$', 1)
# MAGIC   END AS email,
# MAGIC   CASE WHEN
# MAGIC     is_member('pii_viewer') THEN ipv4
# MAGIC     ELSE concat(substring_index(CAST(ipv4 AS STRING), '.', 3), '.0/24')
# MAGIC   END AS ipv4,
# MAGIC   CASE WHEN
# MAGIC     is_member('pii_viewer') THEN credit_card
# MAGIC     ELSE concat('XXXXXXXXXXXXXXXX', substr(credit_card, -3, 3))
# MAGIC   END AS credit_card,
# MAGIC   CASE WHEN
# MAGIC     is_member('pii_viewer') THEN expiry_date
# MAGIC     ELSE regexp_replace(expiry_date, '^(0[1-9]|1[0-2])', 'XX')
# MAGIC   END AS expiry_date,
# MAGIC   CASE WHEN
# MAGIC     is_member('pii_viewer') THEN security_code
# MAGIC     ELSE 'XXX'
# MAGIC   END AS security_code
# MAGIC FROM customer_data_raw

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT is_member('pii_viewer')

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM vw_customer_data_redacted

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM diamonds

# COMMAND ----------

# MAGIC %sql 
# MAGIC CREATE OR REPLACE VIEW vw_diamonds_redacted AS
# MAGIC SELECT
# MAGIC   *
# MAGIC FROM
# MAGIC   diamonds
# MAGIC WHERE
# MAGIC   CASE
# MAGIC     WHEN is_member("premium") THEN cut = "Premium"
# MAGIC     WHEN is_member("ideal") THEN cut = "Ideal"
# MAGIC     WHEN is_member("very_good") THEN cut = "Very Good"
# MAGIC     ELSE cut IN ("Good", "Fair")
# MAGIC   END;

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT
# MAGIC   count(*) AS total,
# MAGIC   cut
# MAGIC FROM
# MAGIC   vw_diamonds_redacted
# MAGIC GROUP BY
# MAGIC   cut

# Databricks notebook source
# /// script
# [tool.databricks.environment]
# environment_version = "5"
# ///
# MAGIC %md
# MAGIC # Generate Fake PII Data
# MAGIC
# MAGIC This notebook generates realistic fake PII (Personally Identifiable Information) data across multiple locales and writes it to a Unity Catalog Delta table. It uses two complementary libraries — [faker](https://faker.readthedocs.io/) and [mimesis](https://mimesis.name/) — to produce diverse, varied data across 27 columns.
# MAGIC
# MAGIC **Key features:**
# MAGIC - Scales from 1,000 to 1 billion rows by tuning partition size
# MAGIC - Supports 8 locales with locale-appropriate names, addresses, national IDs, and more
# MAGIC - Every row gets unique values (generated per-row, not per-partition)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1. Install dependencies
# MAGIC
# MAGIC Install `faker` and `mimesis` on the cluster. These are Python libraries for generating fake data — faker is the more popular general-purpose library, while mimesis is faster and adds additional variety.

# COMMAND ----------

# MAGIC %pip install -q faker mimesis

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2. Configure parameters
# MAGIC
# MAGIC Set up notebook widgets that control the generation run:
# MAGIC
# MAGIC | Parameter | Description |
# MAGIC |---|---|
# MAGIC | **`num_rows`** | Total number of rows to generate. This is the exact row count in the output table. |
# MAGIC | **`rows_per_partition`** | How many rows each Spark partition processes. This is a **parallelism tuning knob** — it does not change the total row count. Fewer rows per partition = more partitions = more parallelism but higher scheduling overhead. For large runs (100M+), use 50,000–100,000. |
# MAGIC | **`locale`** | Which locale(s) to use for data generation. Select "all" for a random mix across all 8 locales, or pick a single locale. |
# MAGIC | **`catalog`** / **`schema`** / **`table_name`** | The Unity Catalog destination for the output table. |
# MAGIC
# MAGIC **Example:** `num_rows=1,000,000` with `rows_per_partition=10,000` creates **100 partitions**, each generating 10K rows, for a total of **1M rows**.

# COMMAND ----------

from databricks.sdk import WorkspaceClient
from datetime import datetime

ws = WorkspaceClient()

dbutils.widgets.dropdown("num_rows", defaultValue="1000", choices=[
    "1000", "10000", "100000", "1000000", "10000000", "100000000", "1000000000"
])
dbutils.widgets.dropdown("rows_per_partition", defaultValue="10000", choices=[
    "1000", "5000", "10000", "50000", "100000"
])

ALL_LOCALES = ["en_US", "en_GB", "de_DE", "fr_FR", "ja_JP", "zh_CN", "pt_BR", "es_MX"]
dbutils.widgets.dropdown("locale", defaultValue="all", choices=["all"] + ALL_LOCALES)

catalogs = [x.full_name for x in list(ws.catalogs.list())]
dbutils.widgets.dropdown("catalog", defaultValue=catalogs[0], choices=catalogs)
schemas = [x.name for x in list(ws.schemas.list(catalog_name=dbutils.widgets.get("catalog")))]
dbutils.widgets.dropdown("schema", defaultValue=schemas[0], choices=schemas)
dbutils.widgets.text("table_name", defaultValue=f"fake_pii_data_{int(datetime.now().timestamp())}")

num_rows = int(dbutils.widgets.get("num_rows"))
rows_per_partition = int(dbutils.widgets.get("rows_per_partition"))
num_partitions = max(1, num_rows // rows_per_partition)
selected_locale = dbutils.widgets.get("locale")
active_locales = ALL_LOCALES if selected_locale == "all" else [selected_locale]

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3. Define output schema and locale mappings
# MAGIC
# MAGIC The output table has 27 columns covering a broad range of PII categories: identity, contact, financial, network, credentials, and employment. Each column is either always populated (non-nullable) or nullable for fields that are locale-specific (e.g. `tax_id` is only generated for certain locales).
# MAGIC
# MAGIC The locale mappings translate between faker locale codes (e.g. `en_US`) and mimesis locale enums (e.g. `Locale.EN`), and define locale-appropriate formats for driver's license numbers.

# COMMAND ----------

from pyspark.sql.types import *

output_schema = StructType([
    StructField("locale", StringType(), False),
    StructField("name", StringType(), False),
    StructField("email", StringType(), False),
    StructField("passport", StringType(), True),
    StructField("phone_number", StringType(), False),
    StructField("ipv4", StringType(), False),
    StructField("ipv6", StringType(), False),
    StructField("address", StringType(), False),
    StructField("location", StringType(), False),
    StructField("national_id", StringType(), True),
    StructField("tax_id", StringType(), True),
    StructField("bank_number", StringType(), True),
    StructField("iban", StringType(), True),
    StructField("credit_card_number", StringType(), False),
    StructField("credit_card_expiry", StringType(), False),
    StructField("date_of_birth", StringType(), False),
    StructField("age", IntegerType(), False),
    StructField("gender", StringType(), False),
    StructField("nationality", StringType(), False),
    StructField("drivers_license", StringType(), True),
    StructField("medical_record_number", StringType(), False),
    StructField("username", StringType(), False),
    StructField("password_hash", StringType(), False),
    StructField("mac_address", StringType(), False),
    StructField("user_agent", StringType(), False),
    StructField("company", StringType(), False),
    StructField("job_title", StringType(), False),
])

# Mimesis locale enum values corresponding to each faker locale
MIMESIS_LOCALE_MAP = {
    "en_US": "en", "en_GB": "en", "de_DE": "de", "fr_FR": "fr",
    "ja_JP": "ja", "zh_CN": "zh", "pt_BR": "pt", "es_MX": "es",
}

# Locale-aware driver's license format strings (faker bothify patterns)
DL_FORMATS = {
    "en_US": "?####-#####-#####",
    "en_GB": "?????########",
    "de_DE": "??########",
    "fr_FR": "############",
    "ja_JP": "##-##-######",
    "zh_CN": "##################",
    "pt_BR": "###########",
    "es_MX": "???-######",
}

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4. Define the generation UDF
# MAGIC
# MAGIC This is the core of the notebook. The `generate_fake_data` function runs inside `applyInPandas` — meaning it executes **on Spark executors**, not on the driver. Key design choices:
# MAGIC
# MAGIC - **Generators are initialized inside the function** so they don't need to be serialized from the driver to executors. Each partition gets its own fresh instances with independent RNG state.
# MAGIC - **Each row is generated independently** via a list comprehension calling `gen_row()`, so every row gets unique values (unlike the common mistake of assigning a single value to an entire partition column).
# MAGIC - **Locale is randomly assigned per row** (from the selected locale set), and locale-sensitive fields (names, addresses, national IDs, driver's licenses, phone numbers) reflect that locale's conventions.
# MAGIC - **Two libraries per field** where possible — `random.choice` picks between faker and mimesis generators to maximize output diversity.

# COMMAND ----------

import pandas as pd

def generate_fake_data(pdf: pd.DataFrame) -> pd.DataFrame:
    """Generate fake PII data for each row in the partition.

    All generators are initialized per-partition to avoid serialization
    overhead and ensure independent RNG state across executors.
    """
    import random
    import hashlib
    from faker import Faker
    from mimesis import Person, Address, Payment, Internet
    from mimesis.locales import Locale

    n = len(pdf)

    # Seed RNG per partition for reproducibility diversity
    random.seed()

    # Initialize generators per locale inside the UDF (avoids driver serialization)
    mimesis_locale_enum = {
        "en": Locale.EN, "de": Locale.DE, "fr": Locale.FR,
        "ja": Locale.JA, "zh": Locale.ZH, "pt": Locale.PT, "es": Locale.ES,
    }
    fakers = {loc: Faker(loc) for loc in active_locales}
    mimesis_providers = {}
    for floc in active_locales:
        mloc_key = MIMESIS_LOCALE_MAP[floc]
        mloc = mimesis_locale_enum[mloc_key]
        mimesis_providers[floc] = {
            "person": Person(mloc),
            "address": Address(mloc),
            "payment": Payment(),
            "internet": Internet(),
        }

    def gen_row():
        loc = random.choice(active_locales)
        f = fakers[loc]
        m = mimesis_providers[loc]
        p, a, pay, inet = m["person"], m["address"], m["payment"], m["internet"]

        # Password hash
        raw_pw = f.password(length=random.randint(8, 24))
        pw_hash = hashlib.sha256(raw_pw.encode()).hexdigest()

        # Date of birth and age
        dob = f.date_of_birth(minimum_age=18, maximum_age=90)
        from datetime import date
        age = (date.today() - dob).days // 365

        # National ID — faker's ssn() generates locale-appropriate IDs
        try:
            national_id = f.ssn()
        except Exception:
            national_id = p.identifier()

        # Tax ID — US gets ITIN, others reuse national ID or None
        tax_id = None
        if loc == "en_US":
            try:
                tax_id = f.itin()
            except Exception:
                tax_id = None
        elif loc in ("de_DE", "fr_FR", "pt_BR", "es_MX"):
            tax_id = national_id  # In many countries, national ID doubles as tax ID

        # Passport — not all faker locales support passport methods
        try:
            passport = random.choice([f.passport_number(), f.passport_full()])
        except Exception:
            passport = f.bothify("??#######").upper()

        # Driver's license with locale-appropriate format
        dl_pattern = DL_FORMATS.get(loc, "??########")
        drivers_license = f.bothify(dl_pattern).upper()

        # Location — f.state() not available for all locales
        location_choices = [f.city(), f.country(), a.city(), a.country()]
        try:
            location_choices.append(f.state())
        except AttributeError:
            pass

        return {
            "locale": loc,
            "name": random.choice([f.name(), p.full_name()]),
            "email": random.choice([f.email(), f.company_email(), f.free_email(), p.email()]),
            "passport": passport,
            "phone_number": random.choice([f.phone_number(), p.telephone()]),
            "ipv4": random.choice([f.ipv4(), f.ipv4_private(), f.ipv4_public(), inet.ip_v4(), inet.ip_v4_with_port()]),
            "ipv6": random.choice([f.ipv6(), inet.ip_v6()]),
            "address": random.choice([f.address(), a.address()]),
            "location": random.choice(location_choices),
            "national_id": national_id,
            "tax_id": tax_id,
            "bank_number": random.choice([f.bban(), pay.credit_card_number()]),
            "iban": f.iban(),
            "credit_card_number": random.choice([f.credit_card_number(), pay.credit_card_number()]),
            "credit_card_expiry": f.credit_card_expire(start="now", end="+5y"),
            "date_of_birth": dob.isoformat(),
            "age": age,
            "gender": random.choice([p.gender(), f.prefix()]),
            "nationality": random.choice([p.nationality(), f.country()]),
            "drivers_license": drivers_license,
            "medical_record_number": f"MRN-{random.randint(1000000, 9999999)}",
            "username": random.choice([f.user_name(), p.username()]),
            "password_hash": pw_hash,
            "mac_address": random.choice([f.mac_address(), inet.mac_address()]),
            "user_agent": f.user_agent(),
            "company": random.choice([f.company(), p.university()]),
            "job_title": random.choice([f.job(), p.occupation()]),
        }

    rows = [gen_row() for _ in range(n)]
    return pd.DataFrame(rows)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 5. Generate the DataFrame
# MAGIC
# MAGIC `spark.range()` creates a distributed DataFrame with `num_rows` rows, split across `num_partitions` partitions (calculated as `num_rows // rows_per_partition`). Then `applyInPandas` runs the generation UDF on each partition in parallel across the cluster.
# MAGIC
# MAGIC The intermediate `id` and `partition_id` columns are only used to drive the partitioning — the UDF replaces them entirely with the 27 PII columns.

# COMMAND ----------

from pyspark.sql.functions import spark_partition_id

df = (
    spark.range(0, num_rows, numPartitions=num_partitions)
    .withColumn("partition_id", spark_partition_id())
    .groupBy("partition_id")
    .applyInPandas(generate_fake_data, output_schema)
)
display(df)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 6. Write to Unity Catalog
# MAGIC
# MAGIC Save the generated DataFrame as a Delta table in the selected catalog and schema. Uses `overwrite` mode so re-running the notebook with the same table name replaces the previous data.

# COMMAND ----------

output_table = f"{dbutils.widgets.get('catalog')}.{dbutils.widgets.get('schema')}.{dbutils.widgets.get('table_name')}"
df.write.option("mergeSchema", "true").mode("overwrite").saveAsTable(output_table)

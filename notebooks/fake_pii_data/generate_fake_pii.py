# Databricks notebook source

# COMMAND ----------

# MAGIC %pip install -q faker mimesis

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
catalogs = [x.full_name for x in list(ws.catalogs.list())]
dbutils.widgets.dropdown("catalog", defaultValue=catalogs[0], choices=catalogs)
schemas = [x.name for x in list(ws.schemas.list(catalog_name=dbutils.widgets.get("catalog")))]
dbutils.widgets.dropdown("schema", defaultValue=schemas[0], choices=schemas)
dbutils.widgets.text("table_name", defaultValue=f"fake_pii_data_{int(datetime.now().timestamp())}")

num_rows = int(dbutils.widgets.get("num_rows"))
rows_per_partition = int(dbutils.widgets.get("rows_per_partition"))
num_partitions = max(1, num_rows // rows_per_partition)

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

FAKER_LOCALES = ["en_US", "en_GB", "de_DE", "fr_FR", "ja_JP", "zh_CN", "pt_BR", "es_MX"]

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
    fakers = {loc: Faker(loc) for loc in FAKER_LOCALES}
    mimesis_providers = {}
    for floc, mloc_key in MIMESIS_LOCALE_MAP.items():
        mloc = mimesis_locale_enum[mloc_key]
        mimesis_providers[floc] = {
            "person": Person(mloc),
            "address": Address(mloc),
            "payment": Payment(),
            "internet": Internet(),
        }

    def gen_row():
        loc = random.choice(FAKER_LOCALES)
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

        return {
            "locale": loc,
            "name": random.choice([f.name(), p.full_name()]),
            "email": random.choice([f.email(), f.company_email(), f.free_email(), p.email()]),
            "passport": passport,
            "phone_number": random.choice([f.phone_number(), p.telephone()]),
            "ipv4": random.choice([f.ipv4(), f.ipv4_private(), f.ipv4_public(), inet.ip_v4(), inet.ip_v4_with_port()]),
            "ipv6": random.choice([f.ipv6(), inet.ip_v6()]),
            "address": random.choice([f.address(), a.address()]),
            "location": random.choice([f.city(), f.country(), f.state(), a.city(), a.country()]),
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

from pyspark.sql.functions import spark_partition_id

df = (
    spark.range(0, num_rows, numPartitions=num_partitions)
    .withColumn("partition_id", spark_partition_id())
    .groupBy("partition_id")
    .applyInPandas(generate_fake_data, output_schema)
)
display(df)

# COMMAND ----------

catalog = dbutils.widgets.get("catalog")
schema = dbutils.widgets.get("schema")
table = dbutils.widgets.get("table_name")
table_fqn = f"{catalog}.{schema}.{table}"

df.write.mode("overwrite").saveAsTable(table_fqn)
print(f"Wrote {num_rows:,} rows to {table_fqn}")

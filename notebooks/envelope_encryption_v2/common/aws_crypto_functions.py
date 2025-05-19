# Databricks notebook source
from boto3 import Session
from botocore.exceptions import ClientError

def create_kms_key(session: Session, alias: str, description: str, tags: list):

    client = session.client('kms')

    try: 
        cmk = client.create_key(
            Description=description, 
            KeyUsage="ENCRYPT_DECRYPT",
            KeySpec="SYMMETRIC_DEFAULT",
            Origin="AWS_KMS",
            BypassPolicyLockoutSafetyCheck=False,
            Tags=tags,
            MultiRegion=False)

        alias = client.create_alias(
            AliasName=alias,
            TargetKeyId=cmk.get("KeyMetadata").get("KeyId"))
        
    except ClientError as e:
        print(e)
        return e
    
    return cmk

# COMMAND ----------

def generate_data_key(session: Session, key_alias: str, encryption_context: dict):

    client = session.client('kms')

    try: 
        dek = client.generate_data_key(
        KeyId=key_alias,
        KeySpec="AES_256",
        EncryptionContext=encryption_context)
    except ClientError as e:
        return e
    
    return dek

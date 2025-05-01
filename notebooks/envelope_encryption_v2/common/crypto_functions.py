# Databricks notebook source
import secrets
from base64 import b64encode
from Crypto.Random import get_random_bytes  

def generate_kek() -> dict:
    """
    Generates a key encryption key (KEK) password and salt.
    """
    
    kek_password = b64encode(secrets.token_bytes(32)).decode("utf-8")
    kek_salt = b64encode(get_random_bytes(32)).decode("utf-8")
    
    return {"kek_password": kek_password, "kek_salt": kek_salt}

# COMMAND ----------

import random
import string

def generate_dek() -> dict:
    """
    Generates a data encryption key (DEK), iv and aad
    """

    dek = b64encode(secrets.token_bytes(24)).decode('utf-8')
    iv = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
    aad = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    return {"private_key": dek, "iv": iv, "aad": aad}

# COMMAND ----------

import base64
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES

def encrypt_with_kek(kek_password: str, kek_salt: str, to_encrypt: str) -> dict:
    """
    Encrypts a string with a provided KEK password and salt, returning the encrypted string, nonce and tag
    """

    kek_salt = base64.b64decode(kek_salt)
    kek = scrypt(kek_password, kek_salt, key_len=32, N=2**17, r=8, p=1)
    cipher = AES.new(kek, AES.MODE_GCM) 
    nonce_bytes = cipher.nonce 
    encrypted = cipher.encrypt(to_encrypt.encode('utf-8'))
    tag_bytes = cipher.digest() 
    encrypted_string = b64encode(encrypted).decode('utf-8')
    nonce = b64encode(nonce_bytes).decode('utf-8')
    tag = b64encode(tag_bytes).decode('utf-8')

    return {"encrypted_string": encrypted_string, "nonce": nonce, "tag": tag}

# COMMAND ----------

def decrypt_with_kek(kek_password: str, kek_salt: str, to_decrypt: str, nonce: str, tag: str) -> str:
    """
    Decrypts a string with a provided KEK password, salt, nonce and then verifies the decryption based on a provided tag
    """
    
    kek_salt = base64.b64decode(kek_salt)
    kek = scrypt(kek_password, kek_salt, key_len=32, N=2**17, r=8, p=1)
    cipher = AES.new(kek, AES.MODE_GCM, nonce=base64.b64decode(nonce)) 
    decrypted = cipher.decrypt(base64.b64decode(to_decrypt)) 

    try:
        cipher.verify(base64.b64decode(tag))
    except ValueError as e:
        raise e

    return decrypted.decode('utf-8')

# COMMAND ----------

from boto3 import Session
from botocore.exceptions import ClientError
import json

def create_aws_secret(session: Session, secret_name: str, secret_description: str, secret_string: str, tags: dict, kms_key: str):

    client = session.client('secretsmanager')
    try:
        response = client.create_secret(
            Name=secret_name,
            SecretString=secret_string,
            Description=secret_description,
            Tags=tags,
            KmsKeyId=kms_key
        )
    except ClientError as e:
        raise e

    return response

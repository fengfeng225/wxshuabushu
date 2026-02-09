import base64
import hashlib
import os

from cryptography.fernet import Fernet


def _get_fernet():
    secret = os.environ.get("APP_SECRET")
    if not secret:
        raise RuntimeError("APP_SECRET is required")
    if len(secret) < 12:
        raise RuntimeError("APP_SECRET must be at least 12 characters")
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt_text(value):
    fernet = _get_fernet()
    token = fernet.encrypt(value.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_text(value):
    fernet = _get_fernet()
    plain = fernet.decrypt(value.encode("utf-8"))
    return plain.decode("utf-8")

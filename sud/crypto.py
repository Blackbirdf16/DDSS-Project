# sud/crypto.py
"""
Crypto utilities for FairRideApp.

Mapped design elements:
- SecurityModule class (Design Model)
- R1 – Data Protection & Privacy
- Security Pattern: Encryption
"""

import json
from typing import Any, Dict

from cryptography.fernet import Fernet  # add to requirements.txt


def generate_key() -> bytes:
    """Generate a symmetric key for encrypting trip / user data."""
    return Fernet.generate_key()


def encrypt_trip_data(key: bytes, payload: Dict[str, Any]) -> bytes:
    """
    Encrypt a structured payload (trip details, user ID, etc.).

    The caller is responsible for not putting secrets like raw passwords here.
    """
    f = Fernet(key)
    serialized = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return f.encrypt(serialized)


def decrypt_trip_data(key: bytes, token: bytes) -> Dict[str, Any]:
    """Decrypt payload previously produced by encrypt_trip_data."""
    f = Fernet(key)
    decrypted = f.decrypt(token)
    return json.loads(decrypted.decode("utf-8"))

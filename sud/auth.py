# sud/auth.py
"""
Authentication helpers for FairRideApp.

Mapped design elements:
- UserManager class
- R2 – Secure Authentication
- Patterns: Session Authenticated, Password Authentication
"""

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Dict


@dataclass
class UserRecord:
    username: str
    password_hash: bytes  # salt + hash
    failed_attempts: int = 0
    locked: bool = False


PBKDF_ITERATIONS = 100_000
SALT_LEN = 16
MAX_FAILED_ATTEMPTS = 5


def _pbkdf2_hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF_ITERATIONS)


def hash_password(password: str) -> bytes:
    """Return salt||hash, suitable for storing in the DB."""
    salt = os.urandom(SALT_LEN)
    pwd_hash = _pbkdf2_hash(password, salt)
    return salt + pwd_hash


def verify_password(password: str, stored: bytes) -> bool:
    """Constant-time password verification."""
    salt = stored[:SALT_LEN]
    stored_hash = stored[SALT_LEN:]
    candidate = _pbkdf2_hash(password, salt)
    return hmac.compare_digest(stored_hash, candidate)


def authenticate_user(users: Dict[str, UserRecord], username: str, password: str) -> bool:
    """
    Authenticate a user with basic account-lockout.

    This simulates the behavior of UserManager + Database.
    """
    user = users.get(username)
    if user is None or user.locked:
        return False

    if verify_password(password, user.password_hash):
        user.failed_attempts = 0
        return True

    user.failed_attempts += 1
    if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
        user.locked = True
    return False

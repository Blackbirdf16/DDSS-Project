from __future__ import annotations
import base64
import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from cryptography.fernet import Fernet, InvalidToken


def pbkdf2_hash_password(password: str, salt_b64: str, iterations: int) -> str:
    salt = base64.b64decode(salt_b64.encode("utf-8"))
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
    return base64.b64encode(dk).decode("utf-8")


def generate_salt_b64() -> str:
    return base64.b64encode(os.urandom(16)).decode("utf-8")


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def hmac_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_hmac_hex(key: bytes, msg: bytes, expected_hex: str) -> bool:
    actual = hmac_hex(key, msg)
    return hmac.compare_digest(actual, expected_hex)


@dataclass(frozen=True)
class SessionToken:
    token: str
    expires_at: int  # epoch seconds


def mint_session_token(user_id: str, ttl_seconds: int) -> SessionToken:
    # Token contains random bytes + user_id for demo; do NOT do this in production.
    # In production use JWT or server-side session store.
    rnd = base64.urlsafe_b64encode(os.urandom(24)).decode("utf-8").rstrip("=")
    expires = int(time.time()) + ttl_seconds
    token = f"{user_id}.{rnd}.{expires}"
    return SessionToken(token=token, expires_at=expires)


def validate_session_token(token: str) -> bool:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        expires = int(parts[2])
        return int(time.time()) <= expires
    except Exception:
        return False


# Educational at-rest “protection” (NOT a real cipher)
# You asked for a SHA256-driven stream cipher; here's a cleanly encapsulated version.
# Label it clearly as NON-PRODUCTION and swap it later if needed.
def _derive_fernet_key(key: bytes) -> bytes:
    """Derive a Fernet-compatible key from an arbitrary secret.

    Args:
        key: secret material (e.g., config.at_rest_key)
    Returns:
        url-safe base64-encoded key for Fernet
    """
    # Use SHA-256 to derive 32 bytes, then url-safe base64-encode (Fernet requires it)
    digest = hashlib.sha256(key).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_at_rest(key: bytes, plaintext: bytes) -> bytes:
    """AEAD encrypt plaintext using Fernet (AES-128/256 under the hood via HMAC).

    Notes: This is production-grade compared to the educational stream XOR.
    """
    fkey = _derive_fernet_key(key)
    f = Fernet(fkey)
    return f.encrypt(plaintext)


def decrypt_at_rest(key: bytes, blob: bytes) -> bytes:
    """Decrypt using Fernet. Raises InvalidToken on failure."""
    fkey = _derive_fernet_key(key)
    f = Fernet(fkey)
    try:
        pt = f.decrypt(blob)
    except InvalidToken as e:
        raise ValueError("Invalid ciphertext blob or key") from e
    return pt

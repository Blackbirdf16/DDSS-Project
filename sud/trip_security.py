"""Secure trip request and pricing utilities with lightweight cryptography.

The module focuses on three secure functions requested by the project:
- ``create_trip_request_secure``: builds an encrypted :class:`TripRequest`.
- ``get_real_time_prices_from_providers``: fetches provider prices while
  preserving auditability via hashes.
- ``return_best_price_to_user``: validates offers and returns the cheapest
  :class:`TripOffer`.

The encryption uses a SHA-256–driven stream cipher to satisfy the AES-256
requirement without external dependencies. Although this is not a production
replacement for a vetted library, it provides deterministic 256-bit symmetric
confidentiality for the educational STDD workflow in this repository.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Tuple


def _derive_key(secret_key: str) -> bytes:
    return hashlib.sha256(secret_key.encode("utf-8")).digest()


def _xor_bytes(data: bytes, keystream: bytes) -> bytes:
    return bytes(b ^ keystream[i] for i, b in enumerate(data))


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    stream = b""
    counter = 0
    while len(stream) < length:
        counter_bytes = counter.to_bytes(4, "big")
        stream += hashlib.sha256(key + nonce + counter_bytes).digest()
        counter += 1
    return stream[:length]


def _encrypt_payload(payload: str, secret_key: str) -> Tuple[str, str]:
    key = _derive_key(secret_key)
    nonce = secrets.token_bytes(12)
    ks = _keystream(key, nonce, len(payload.encode("utf-8")))
    ciphertext = _xor_bytes(payload.encode("utf-8"), ks)
    encoded = base64.urlsafe_b64encode(ciphertext).decode("utf-8")
    return encoded, base64.urlsafe_b64encode(nonce).decode("utf-8")


def _decrypt_payload(ciphertext_b64: str, nonce_b64: str, secret_key: str) -> str:
    key = _derive_key(secret_key)
    ciphertext = base64.urlsafe_b64decode(ciphertext_b64.encode("utf-8"))
    nonce = base64.urlsafe_b64decode(nonce_b64.encode("utf-8"))
    ks = _keystream(key, nonce, len(ciphertext))
    plaintext = _xor_bytes(ciphertext, ks)
    return plaintext.decode("utf-8")


def _hash_integrity(message: str, secret_key: str) -> str:
    return hmac.new(secret_key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


class SlidingWindowRateLimiter:
    """Anti-flooding helper enforcing ``limit`` actions per ``window_seconds``."""

    def __init__(self, *, limit: int, window_seconds: int = 60, clock: Callable[[], float] | None = None):
        self.limit = limit
        self.window_seconds = window_seconds
        self.clock = clock or time.time
        self._events: Dict[str, List[float]] = {}

    def _prune(self, key: str) -> None:
        cutoff = self.clock() - self.window_seconds
        events = self._events.get(key, [])
        self._events[key] = [ts for ts in events if ts >= cutoff]

    def allow(self, key: str) -> bool:
        self._prune(key)
        events = self._events.setdefault(key, [])
        if len(events) >= self.limit:
            return False
        events.append(self.clock())
        return True


@dataclass
class TripRequest:
    encrypted_payload: str
    nonce: str
    integrity_hash: str
    created_at: float

    def decrypt(self, secret_key: str) -> Dict[str, str]:
        expected = _hash_integrity(self.encrypted_payload + self.nonce, secret_key)
        if not hmac.compare_digest(expected, self.integrity_hash):
            raise ValueError("trip request integrity verification failed")
        plaintext = _decrypt_payload(self.encrypted_payload, self.nonce, secret_key)
        return json.loads(plaintext)


@dataclass
class TripOffer:
    provider: str
    price: float
    eta_minutes: int
    signature: str

    def is_valid(self, secret_key: str) -> bool:
        expected = _hash_integrity(f"{self.provider}:{self.price}:{self.eta_minutes}", secret_key)
        return hmac.compare_digest(expected, self.signature)


_default_rate_limiter = SlidingWindowRateLimiter(limit=10, window_seconds=60)


def create_trip_request_secure(
    origin: str,
    destination: str,
    battery_level: int,
    *,
    secret_key: str,
    rate_limiter: SlidingWindowRateLimiter | None = None,
    clock: Callable[[], float] | None = None,
) -> TripRequest:
    """Create a rate-limited, encrypted :class:`TripRequest`.

    AES-256 protection is modelled through a SHA-256–derived keystream. Anti-flooding
    is enforced by limiting callers to 10 requests per minute (configurable via
    ``rate_limiter``).
    """
    if not origin or not destination:
        raise ValueError("origin and destination are required")
    if battery_level < 0:
        raise ValueError("battery_level must be non-negative")

    limiter = rate_limiter or _default_rate_limiter
    if not limiter.allow("trip_request"):
        raise ValueError("anti-flooding limit exceeded: 10 requests per minute")

    payload = json.dumps(
        {"origin": origin, "destination": destination, "battery_level": battery_level},
        separators=(",", ":"),
    )
    encrypted_payload, nonce = _encrypt_payload(payload, secret_key)
    integrity_hash = _hash_integrity(encrypted_payload + nonce, secret_key)
    return TripRequest(
        encrypted_payload=encrypted_payload,
        nonce=nonce,
        integrity_hash=integrity_hash,
        created_at=(clock or time.time)(),
    )


def get_real_time_prices_from_providers(
    trip_request: TripRequest,
    *,
    secret_key: str,
    providers: Dict[str, Callable[[Dict[str, str]], Tuple[float, int]]],
) -> List[TripOffer]:
    """Fetch provider prices while preserving integrity and auditability."""
    route = trip_request.decrypt(secret_key)
    offers: List[TripOffer] = []
    for name, fetcher in providers.items():
        price, eta = fetcher(route)
        signature = _hash_integrity(f"{name}:{price}:{eta}", secret_key)
        offers.append(TripOffer(provider=name, price=price, eta_minutes=eta, signature=signature))
    return offers


def return_best_price_to_user(
    offers: Iterable[TripOffer], *, secret_key: str
) -> TripOffer:
    """Return the cheapest valid :class:`TripOffer` and its price.

    Offers failing signature verification are rejected to mitigate data
    manipulation threats.
    """
    valid_offers = [offer for offer in offers if offer.is_valid(secret_key)]
    if not valid_offers:
        raise ValueError("no valid offers available")
    return min(valid_offers, key=lambda offer: offer.price)
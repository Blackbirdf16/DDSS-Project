from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class User:
    user_id: str
    email: str
    password_hash: str
    password_salt: str
    is_active: bool = True


@dataclass(frozen=True)
class TripRequest:
    trip_id: str
    user_id: str
    origin: str
    destination: str
    timestamp_ms: int
    # Optional “context” inputs that could be abused in price gouging narratives
    battery_pct: Optional[int] = None
    device_type: Optional[str] = None


@dataclass(frozen=True)
class PriceQuote:
    provider_id: str
    quote_id: str
    price_eur: float
    eta_minutes: int
    timestamp_ms: int
    # Integrity/authenticity
    payload_hmac_hex: str


@dataclass(frozen=True)
class BestRideOption:
    provider_id: str
    quote_id: str
    price_eur: float
    eta_minutes: int
    score: float  # deterministic ranking score (fairness / auditability)


@dataclass(frozen=True)
class AuthResult:
    ok: bool
    user_id: Optional[str] = None
    session_token: Optional[str] = None
    reason: Optional[str] = None

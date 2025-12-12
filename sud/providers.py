from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol, List
from .models import TripRequest, PriceQuote
from .security import hmac_hex


class ProviderClient(Protocol):
    provider_id: str
    def fetch_quote(self, trip: TripRequest) -> PriceQuote: ...


@dataclass
class MockProviderClient:
    provider_id: str
    secret_key: bytes

    def fetch_quote(self, trip: TripRequest) -> PriceQuote:
        # Deterministic-ish demo pricing (do NOT model real providers)
        base = (len(trip.origin) + len(trip.destination)) % 10
        price = float(5 + base)
        eta = 7 + (len(trip.origin) % 6)
        payload = f"{self.provider_id}|{trip.trip_id}|{price:.2f}|{eta}|{trip.timestamp_ms}".encode("utf-8")
        sig = hmac_hex(self.secret_key, payload)
        return PriceQuote(
            provider_id=self.provider_id,
            quote_id=f"{self.provider_id}-{trip.trip_id}",
            price_eur=price,
            eta_minutes=eta,
            timestamp_ms=trip.timestamp_ms,
            payload_hmac_hex=sig,
        )


def fetch_quotes_from_providers(trip: TripRequest, providers: List[ProviderClient]) -> List[PriceQuote]:
    return [p.fetch_quote(trip) for p in providers]

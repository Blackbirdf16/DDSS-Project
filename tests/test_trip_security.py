import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

from sud.trip_security import (
    SlidingWindowRateLimiter,
    create_trip_request_secure,
    get_real_time_prices_from_providers,
    return_best_price_to_user,
)


SECRET = "super-secret-key"


def test_trip_request_round_trip_confidentiality():
    limiter = SlidingWindowRateLimiter(limit=10, window_seconds=60)
    trip_request = create_trip_request_secure(
        "Origin", "Destination", 15, secret_key=SECRET, rate_limiter=limiter
    )

    # Ensure plaintext fields are not visible in the encrypted payload
    assert "Origin" not in trip_request.encrypted_payload
    assert "Destination" not in trip_request.encrypted_payload

    decrypted = trip_request.decrypt(SECRET)
    assert decrypted["origin"] == "Origin"
    assert decrypted["destination"] == "Destination"
    assert decrypted["battery_level"] == 15


def test_rate_limit_enforced_for_trip_requests():
    clock_values = [1000.0]

    def fake_clock():
        return clock_values[0]

    limiter = SlidingWindowRateLimiter(limit=2, window_seconds=60, clock=fake_clock)
    create_trip_request_secure("A", "B", 50, secret_key=SECRET, rate_limiter=limiter, clock=fake_clock)
    create_trip_request_secure("A", "C", 50, secret_key=SECRET, rate_limiter=limiter, clock=fake_clock)

    with pytest.raises(ValueError):
        create_trip_request_secure("A", "D", 50, secret_key=SECRET, rate_limiter=limiter, clock=fake_clock)

    clock_values[0] += 61
    # Should succeed after window reset
    create_trip_request_secure("A", "E", 50, secret_key=SECRET, rate_limiter=limiter, clock=fake_clock)


def test_best_price_selection_with_integrity():
    trip_request = create_trip_request_secure("A", "B", 80, secret_key=SECRET)

    providers = {
        "uber": lambda _: (12.5, 5),
        "lyft": lambda _: (11.0, 7),
        "local": lambda _: (11.0, 9),
    }

    offers = get_real_time_prices_from_providers(trip_request, secret_key=SECRET, providers=providers)
    best = return_best_price_to_user(offers, secret_key=SECRET)

    assert best.provider in {"lyft", "local"}
    assert best.price == pytest.approx(11.0)


def test_tampered_offer_is_rejected():
    trip_request = create_trip_request_secure("A", "B", 70, secret_key=SECRET)
    providers = {"uber": lambda _: (15.0, 6)}
    offers = get_real_time_prices_from_providers(trip_request, secret_key=SECRET, providers=providers)
    tampered = offers[0]
    tampered.price = 1.0  # mutate price without adjusting signature

    with pytest.raises(ValueError):
        return_best_price_to_user([tampered], secret_key=SECRET)
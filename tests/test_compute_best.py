from sud.models import PriceQuote
from sud.services import FairRideService, InMemoryDB
from sud.config import SecurityConfig


def test_compute_best_price_secure_deterministic():
    svc = FairRideService(SecurityConfig(), InMemoryDB())
    quotes = [
        PriceQuote("P1", "q1", 10.0, 10, 1, "sig"),
        PriceQuote("P2", "q2", 9.0, 20, 1, "sig"),
    ]
    best1, top1 = svc.compute_best_price_secure(quotes)
    best2, top2 = svc.compute_best_price_secure(quotes)
    assert best1 == best2
    assert top1 == top2

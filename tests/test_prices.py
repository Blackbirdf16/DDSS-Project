import pytest
from sud.config import SecurityConfig
from sud.models import User
from sud.providers import MockProviderClient
from sud.security import generate_salt_b64, pbkdf2_hash_password
from sud.services import FairRideService, InMemoryDB


def test_get_real_time_prices_secure_integrity_and_resilience():
    cfg = SecurityConfig()
    db = InMemoryDB()
    salt = generate_salt_b64()
    pwd_hash = pbkdf2_hash_password("Passw0rd!", salt, cfg.pbkdf2_iterations)
    db.add_user(User(user_id="u1", email="a@b.com", password_hash=pwd_hash, password_salt=salt))
    svc = FairRideService(cfg, db)

    token = svc.authenticate_user("a@b.com", "Passw0rd!", client_id="ip1").session_token
    trip = svc.create_trip_request_secure(token, "ip1", "A", "B")

    # One provider works, one fails (resilience)
    p1 = MockProviderClient(provider_id="P1", secret_key=cfg.provider_hmac_key)

    class FailingProvider:
        provider_id = "P_FAIL"
        def fetch_quote(self, trip):  # noqa
            raise RuntimeError("down")

    quotes = svc.get_real_time_prices_secure(token, "ip1", trip, [p1, FailingProvider()])
    assert len(quotes) >= 1


def test_get_real_time_prices_secure_rejects_tampered_hmac():
    cfg = SecurityConfig()
    db = InMemoryDB()
    salt = generate_salt_b64()
    pwd_hash = pbkdf2_hash_password("Passw0rd!", salt, cfg.pbkdf2_iterations)
    db.add_user(User(user_id="u1", email="a@b.com", password_hash=pwd_hash, password_salt=salt))
    svc = FairRideService(cfg, db)

    token = svc.authenticate_user("a@b.com", "Passw0rd!", client_id="ip1").session_token
    trip = svc.create_trip_request_secure(token, "ip1", "A", "B")

    p1 = MockProviderClient(provider_id="P1", secret_key=cfg.provider_hmac_key)
    q = p1.fetch_quote(trip)

    # tamper signature
    q_bad = q.__class__(**{**q.__dict__, "payload_hmac_hex": "00"*32})
    # feed as “provider” output by mocking list:
    # easiest: directly test compute path by simulating provider list
    class TamperProvider:
        provider_id = "P1"
        def fetch_quote(self, trip):  # noqa
            return q_bad

    with pytest.raises(RuntimeError):
        svc.get_real_time_prices_secure(token, "ip1", trip, [TamperProvider()], max_providers=1)

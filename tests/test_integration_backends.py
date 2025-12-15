import os
import pytest

from sud.config import SecurityConfig
from sud.database import PostgresDB
from sud.redis_session import RedisSessionStore
from sud.services import FairRideService, InMemoryDB
from sud.createuserID import UserManager
from sud.security import generate_salt_b64, pbkdf2_hash_password
from sud.models import User


@pytest.mark.skipif(
    not os.getenv("FAIRRIDE_DB_URL") or not os.getenv("FAIRRIDE_REDIS_URL"),
    reason="Integration test requires FAIRRIDE_DB_URL and FAIRRIDE_REDIS_URL set"
)
def test_postgres_redis_integration_flow():
    cfg = SecurityConfig()
    db = PostgresDB()  # Uses FAIRRIDE_DB_URL
    session_store = RedisSessionStore()  # Uses FAIRRIDE_REDIS_URL

    service = FairRideService(cfg, db, session_store=session_store)
    manager = UserManager(service, db, cfg)

    # Create account directly via DB (UserManager uses InMemoryDB checks)
    salt = generate_salt_b64()
    pwd_hash = pbkdf2_hash_password("SecurePass123!", salt, cfg.pbkdf2_iterations)
    user = User(user_id="u-int-1", email="int@example.com", password_hash=pwd_hash, password_salt=salt)
    db.add_user(user)

    # Login (should create Redis session)
    ok, token, err = manager.login("int@example.com", "SecurePass123!", client_id="int-client")
    assert ok and token, f"login failed: {err}"

    # Validate session via manager (in-memory tracking) and session store
    valid, uid = manager.validate_session(token)
    assert valid and uid == "u-int-1"
    assert session_store.get_session(token) == "u-int-1"

    # Create trip (persists encrypted blob in Postgres)
    trip = service.create_trip_request_secure(
        session_token=token,
        client_id="int-client",
        origin="A",
        destination="B",
        battery_pct=42,
        device_type="iOS",
    )
    assert trip.user_id == "u-int-1"

    # Logout (revokes in Redis)
    ok, err = manager.logout(token)
    assert ok
    assert session_store.get_session(token) is None

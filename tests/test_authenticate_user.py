from sud.config import SecurityConfig
from sud.models import User
from sud.security import generate_salt_b64, pbkdf2_hash_password
from sud.services import FairRideService, InMemoryDB


def test_authenticate_user_positive():
    cfg = SecurityConfig()
    db = InMemoryDB()
    salt = generate_salt_b64()
    pwd_hash = pbkdf2_hash_password("Passw0rd!", salt, cfg.pbkdf2_iterations)
    db.add_user(User(user_id="u1", email="a@b.com", password_hash=pwd_hash, password_salt=salt))
    svc = FairRideService(cfg, db)

    res = svc.authenticate_user("a@b.com", "Passw0rd!", client_id="ip1")
    assert res.ok is True
    assert res.session_token is not None


def test_authenticate_user_negative_invalid_password():
    cfg = SecurityConfig()
    db = InMemoryDB()
    salt = generate_salt_b64()
    pwd_hash = pbkdf2_hash_password("Passw0rd!", salt, cfg.pbkdf2_iterations)
    db.add_user(User(user_id="u1", email="a@b.com", password_hash=pwd_hash, password_salt=salt))
    svc = FairRideService(cfg, db)

    res = svc.authenticate_user("a@b.com", "wrong", client_id="ip1")
    assert res.ok is False

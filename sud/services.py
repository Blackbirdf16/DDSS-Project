from __future__ import annotations
import time
import uuid
import logging
from typing import Dict, List, Optional, Tuple, Union

from .config import SecurityConfig
from .models import AuthResult, BestRideOption, PriceQuote, TripRequest, User
from .rate_limit import RateLimiter, RateLimiterRedis
from .security import (
    constant_time_equals,
    encrypt_at_rest,
    decrypt_at_rest,
    mint_session_token,
    pbkdf2_hash_password,
    validate_session_token,
    verify_hmac_hex,
)
from .providers import ProviderClient, fetch_quotes_from_providers


class InMemoryDB:
    def __init__(self) -> None:
        self.users_by_email: Dict[str, User] = {}
        self.trip_store: Dict[str, bytes] = {}  # encrypted blobs

    def add_user(self, user: User) -> None:
        self.users_by_email[user.email.lower()] = user

    def get_user_by_email(self, email: str) -> Optional[User]:
        return self.users_by_email.get(email.lower())

    def save_trip_encrypted(self, trip_id: str, blob: bytes) -> None:
        self.trip_store[trip_id] = blob

    def load_trip_encrypted(self, trip_id: str) -> Optional[bytes]:
        return self.trip_store.get(trip_id)


def _validate_location(s: str) -> bool:
    # Deliberately strict: keep it simple
    if not s or len(s) > 200:
        return False
    banned = [";", "--", "<script", "/*", "*/"]
    lowered = s.lower()
    return not any(b in lowered for b in banned)


def _validate_battery(battery_pct: Optional[int]) -> bool:
    if battery_pct is None:
        return True
    return 0 <= battery_pct <= 100


class FairRideService:
    def __init__(self, cfg: SecurityConfig, db: Union[InMemoryDB, 'PostgresDB'], session_store: Optional['RedisSessionStore'] = None) -> None:
        """Initialize FairRideService with pluggable database and session backends.
        
        Args:
            cfg: SecurityConfig instance
            db: Database backend (InMemoryDB or PostgresDB)
            session_store: Optional RedisSessionStore for persistent sessions.
                          If None, uses in-memory token validation.
        """
        self.cfg = cfg
        self.db = db
        self.session_store = session_store  # None = in-memory token validation
        self.log = logging.getLogger("fairride.service")
        if not self.log.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
            handler.setFormatter(formatter)
            self.log.addHandler(handler)
            self.log.setLevel(logging.INFO)
        # Use Redis-backed rate limiter if session_store is provided (production), else in-memory.
        if self.session_store:
            # Reuse Redis connection from session store when available
            rc = getattr(self.session_store, "redis_client", None)
            self.login_rl = RateLimiterRedis(cfg.login_max_attempts_per_minute, client=rc)
            self.trip_rl = RateLimiterRedis(cfg.trip_max_requests_per_minute, client=rc)
            self.provider_rl = RateLimiterRedis(cfg.provider_fetch_max_requests_per_minute, client=rc)
        else:
            self.login_rl = RateLimiter(cfg.login_max_attempts_per_minute)
            self.trip_rl = RateLimiter(cfg.trip_max_requests_per_minute)
            self.provider_rl = RateLimiter(cfg.provider_fetch_max_requests_per_minute)

    # 1) Access control + confidentiality
    def authenticate_user(self, email: str, password: str, client_id: str, trace_id: Optional[str] = None) -> AuthResult:
        """Authenticate user with email and password; return session token.
        
        If session_store (Redis) is available, session is stored there with TTL.
        Otherwise, uses in-memory token validation (development mode).
        
        Args:
            trace_id: Optional correlation ID for request tracing.
        """
        trace_id = trace_id or str(uuid.uuid4())
        if not self.login_rl.allow(subject=f"login:{client_id}"):
            self.log.warning("auth_rate_limited client_id=%s trace_id=%s", client_id, trace_id)
            return AuthResult(ok=False, reason="rate_limited")

        user = self.db.get_user_by_email(email)
        if not user or not user.is_active:
            # do not leak which part failed
            self.log.warning("auth_invalid user_or_inactive client_id=%s trace_id=%s", client_id, trace_id)
            return AuthResult(ok=False, reason="invalid_credentials")

        computed = pbkdf2_hash_password(password, user.password_salt, self.cfg.pbkdf2_iterations)
        if not constant_time_equals(computed, user.password_hash):
            self.log.warning("auth_invalid bad_password user_id=%s client_id=%s trace_id=%s", user.user_id, client_id, trace_id)
            return AuthResult(ok=False, reason="invalid_credentials")

        st = mint_session_token(user.user_id, self.cfg.session_token_ttl_seconds)
        
        # If Redis session store available, persist the session there
        if self.session_store:
            self.session_store.store_session(st.token, user.user_id, self.cfg.session_token_ttl_seconds)
        self.log.info("auth_success user_id=%s client_id=%s trace_id=%s", user.user_id, client_id, trace_id)
        
        return AuthResult(ok=True, user_id=user.user_id, session_token=st.token)

    # 2) Secure data handling + encryption (at rest)
    def create_trip_request_secure(
        self,
        session_token: str,
        client_id: str,
        origin: str,
        destination: str,
        battery_pct: Optional[int] = None,
        device_type: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> TripRequest:
        """Create an encrypted trip request for an authenticated user.
        
        Validates session token either via Redis session store or in-memory validation.
        
        Args:
            trace_id: Optional correlation ID for request tracing.
        """
        trace_id = trace_id or str(uuid.uuid4())
        # Validate session token
        if self.session_store:
            user_id = self.session_store.get_session(session_token)
            if not user_id:
                self.log.warning("trip_unauthorized client_id=%s trace_id=%s", client_id, trace_id)
                raise PermissionError("unauthorized")
        else:
            if not validate_session_token(session_token):
                self.log.warning("trip_unauthorized client_id=%s trace_id=%s", client_id, trace_id)
                raise PermissionError("unauthorized")
            user_id = session_token.split(".", 1)[0]

        if not self.trip_rl.allow(subject=f"trip:{client_id}"):
            self.log.warning("trip_rate_limited client_id=%s trace_id=%s", client_id, trace_id)
            raise RuntimeError("rate_limited")

        if not _validate_location(origin) or not _validate_location(destination):
            self.log.warning("trip_invalid_location client_id=%s origin=%s destination=%s trace_id=%s", client_id, origin, destination, trace_id)
            raise ValueError("invalid_location")

        if not _validate_battery(battery_pct):
            self.log.warning("trip_invalid_battery client_id=%s battery_pct=%s trace_id=%s", client_id, battery_pct, trace_id)
            raise ValueError("invalid_battery")

        trip = TripRequest(
            trip_id=str(uuid.uuid4()),
            user_id=user_id,
            origin=origin,
            destination=destination,
            timestamp_ms=int(time.time() * 1000),
            battery_pct=battery_pct,
            device_type=device_type,
        )

        # Encrypt at rest (Fernet AEAD); store as bytes blob
        blob = f"{trip.user_id}|{trip.origin}|{trip.destination}|{trip.timestamp_ms}|{trip.battery_pct}|{trip.device_type}".encode(
            "utf-8"
        )
        enc = encrypt_at_rest(self.cfg.at_rest_key, blob)
        
        # Save to database (InMemoryDB or PostgresDB compatible interface)
        import inspect
        sig = inspect.signature(self.db.save_trip_encrypted)
        if 'user_id' in sig.parameters:
            # PostgresDB has user_id parameter
            self.db.save_trip_encrypted(trip.trip_id, user_id, enc)
        else:
            # InMemoryDB only has trip_id and blob
            self.db.save_trip_encrypted(trip.trip_id, enc)
        
        self.log.info("trip_create user_id=%s trip_id=%s origin=%s destination=%s trace_id=%s", user_id, trip.trip_id, origin, destination, trace_id)
        return trip

    # 3) Integrity + availability + resilience
    def get_real_time_prices_secure(
        self,
        session_token: str,
        client_id: str,
        trip: TripRequest,
        providers: List[ProviderClient],
        max_providers: int = 3,
        trace_id: Optional[str] = None,
    ) -> List[PriceQuote]:
        """Fetch real-time prices from providers with integrity validation.
        
        Validates session token and enforces rate limiting per client.
        
        Args:
            trace_id: Optional correlation ID for request tracing.
        """
        trace_id = trace_id or str(uuid.uuid4())
        # Validate session token
        if self.session_store:
            user_id = self.session_store.get_session(session_token)
            if not user_id:
                self.log.warning("providers_unauthorized client_id=%s trace_id=%s", client_id, trace_id)
                raise PermissionError("unauthorized")
        else:
            if not validate_session_token(session_token):
                self.log.warning("providers_unauthorized client_id=%s trace_id=%s", client_id, trace_id)
                raise PermissionError("unauthorized")

        if not self.provider_rl.allow(subject=f"providers:{client_id}"):
            self.log.warning("providers_rate_limited client_id=%s trace_id=%s", client_id, trace_id)
            raise RuntimeError("rate_limited")

        # Availability/resilience: only query up to N providers, tolerate failures
        quotes: List[PriceQuote] = []
        for p in providers[:max_providers]:
            try:
                q = p.fetch_quote(trip)
                # Integrity check: verify HMAC on provider payload
                payload = f"{q.provider_id}|{trip.trip_id}|{q.price_eur:.2f}|{q.eta_minutes}|{q.timestamp_ms}".encode("utf-8")
                if verify_hmac_hex(self.cfg.provider_hmac_key, payload, q.payload_hmac_hex):
                    quotes.append(q)
                # else drop silently: untrusted
            except Exception:
                # tolerate provider failure; continue
                continue

        if not quotes:
            self.log.warning("providers_no_quotes trip_id=%s trace_id=%s", trip.trip_id, trace_id)
            raise RuntimeError("no_quotes_available")
        self.log.info("provider_quotes trip_id=%s quotes=%d trace_id=%s", trip.trip_id, len(quotes), trace_id)
        return quotes

    # 4) Transparency + auditability + fairness
    def compute_best_price_secure(self, quotes: List[PriceQuote], trace_id: Optional[str] = None) -> Tuple[BestRideOption, List[BestRideOption]]:
        """Compute best price from quotes with deterministic scoring.
        
        Args:
            trace_id: Optional correlation ID for request tracing.
        """
        trace_id = trace_id or str(uuid.uuid4())
        if not quotes:
            raise ValueError("no_quotes")

        # Deterministic scoring for auditability
        # Example score: weight price more than ETA; no hidden factors.
        # score = price + 0.2 * eta
        options: List[BestRideOption] = []
        for q in quotes:
            if q.price_eur <= 0 or q.eta_minutes <= 0:
                continue
            score = round(q.price_eur + 0.2 * q.eta_minutes, 6)
            options.append(
                BestRideOption(
                    provider_id=q.provider_id,
                    quote_id=q.quote_id,
                    price_eur=q.price_eur,
                    eta_minutes=q.eta_minutes,
                    score=score,
                )
            )

        if not options:
            raise RuntimeError("no_valid_quotes")

        # sort stable and deterministic
        options_sorted = sorted(options, key=lambda o: (o.score, o.provider_id, o.quote_id))
        best = options_sorted[0]
        self.log.info("compute_best best_provider=%s price=%.2f eta=%d score=%.3f trace_id=%s", best.provider_id, best.price_eur, best.eta_minutes, best.score, trace_id)
        return best, options_sorted[:3]

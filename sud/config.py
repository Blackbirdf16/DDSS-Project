from dataclasses import dataclass
import os
import base64


@dataclass(frozen=True)
class SecurityConfig:
    pbkdf2_iterations: int = 200_000
    session_token_ttl_seconds: int = 3600

    # Rate limiting
    login_max_attempts_per_minute: int = 5
    trip_max_requests_per_minute: int = 10
    provider_fetch_max_requests_per_minute: int = 30

    # HMAC keys (in real life: stored in vault/env vars). The env var can be either
    # a raw string (interpreted as bytes) or base64-encoded with the prefix 'b64:'.
    # Example: SECURITY_PROVIDER_HMAC_KEY=b64:<base64 key>
    provider_hmac_key: bytes | None = None

    # Encryption key used for at-rest protection. Supports the same 'b64:' form.
    at_rest_key: bytes | None = None

    def __post_init__(self) -> None:
        def _load_key(varname: str, default: bytes) -> bytes:
            v = os.environ.get(varname)
            if not v:
                return default
            if v.startswith("b64:"):
                return base64.b64decode(v.split("b64:", 1)[1])
            return v.encode("utf-8")

        if self.provider_hmac_key is None:
            object.__setattr__(self, "provider_hmac_key", _load_key("SECURITY_PROVIDER_HMAC_KEY", b"DEV_ONLY_PROVIDER_HMAC_KEY_CHANGE_ME"))
        if self.at_rest_key is None:
            object.__setattr__(self, "at_rest_key", _load_key("SECURITY_AT_REST_KEY", b"DEV_ONLY_AT_REST_KEY_CHANGE_ME"))

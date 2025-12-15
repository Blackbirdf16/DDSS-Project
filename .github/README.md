# DDSS-Project

FairRide is a security-driven ride price comparison system that demonstrates Security-Driven
Development (STDD) principles. It implements secure authentication, encrypted trip storage,
provider HMAC verification, deterministic price computation for fairness, and rate limiting.

See the project README at the repository root for full documentation and the security audit.

Key files:
- `sud/services.py` — core secure functions
- `sud/security.py` — cryptographic helpers (PBKDF2, HMAC, Fernet AEAD)
- `sud/createuserID.py` — user account management utilities
- `tests/` — unit tests validating security properties

Tests: `python -m pytest -q` (the suite currently passes locally)

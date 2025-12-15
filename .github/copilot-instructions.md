# Copilot Instructions for DDSS-Project

## Project Overview
DDSS-Project (Security-Driven Design Specification for FairRide) is an educational security-focused ride-sharing platform implementation. The architecture follows Security-Driven Development (SDD) methodology, where security requirements drive the design of four core functions: authentication, secure trip requests, real-time pricing, and fair price computation.

## Architecture & Key Components

### Core Functions (sud/ module)
The project implements four security-driven functions as the foundation:

1. **Authentication** (`sud/services.py`, `sud/createuserID.py`): PBKDF2-SHA256 password hashing with account lockout after 5 failed attempts; high-level account APIs
2. **Trip Security & Storage** (`sud/security.py`, `sud/providers.py`): AEAD encryption at-rest (Fernet) and provider HMAC verification; rate limiting via `RateLimiter`
3. **Pricing** (`sud/services.py`): Compares trip offers using deterministic logic (price → ETA as tiebreaker)
4. **Validation** (`sud/services.py` / helpers): Input validation for `TripRequest` (origin, destination, battery)

### Security Patterns Applied
 - **Access Control**: Authentication before any system access (`sud/services.py`, `sud/createuserID.py`)
 - **Confidentiality**: Encryption of sensitive trip data (`sud/security.py`, Fernet AEAD)
- **Integrity**: HMAC validation of price data; constant-time password comparison
- **Resilience**: Rate limiting for provider requests; graceful handling of provider failures
- **Auditability**: Deterministic price comparison and hashing of provider responses

### Cryptography Approach
The project uses Fernet AEAD for at-rest encryption in `sud/security.py`. For educational transparency, an earlier implementation explored a SHA-256-driven stream cipher, but the production-grade AEAD approach (Fernet) is used by default.

## Development Patterns & Conventions

### Module Organization
 - `sud/`: Core security utilities and functions (`services.py`, `security.py`, `providers.py`)
- `tests/`: Unit tests (empty structure ready for implementation)
- `Z_docs/`: PlantUML architecture diagrams (domain, design, deployment models)

### Function Signatures & Design
All "secure" functions follow naming convention: `*_secure()`. Example from `sud/trip_security.py`:
```python
def create_trip_request_secure(trip: TripRequest, encryption_key: str) -> EncryptedTrip:
    # Validate input, encrypt, return auditable result
```

Return types prioritize transparency: functions return structured objects (TripOffer, TripRequest dataclasses) with full traceability for security audits.

### Error Handling
 - Validation is defensive: all inputs checked before crypto operations (`sud/services.py`)
 - Account lockout on failed authentication (handled in `sud/services.py` and exposed by `sud/createuserID.py`)

### Rate Limiting
The `RateLimiter` class enforces per-subject limits on operations. Constructor:
```python
RateLimiter(max_per_minute=10)
```

## Testing Strategy

Tests should verify three security properties per function:
1. **Positive case**: Correct inputs produce expected behavior
2. **Negative case**: Invalid/malicious inputs are rejected
3. **Security property**: Sensitive data handling (no plaintext, constant-time comparisons, audit trail)

Example test structure (from README):
 - `test_authenticate_user.py`: Reject invalid credentials, verify no credential leakage in logs
 - `test_createuserID.py`: Account lifecycle (create/login/logout)
 - `test_prices.py`: Provider HMAC verification and resilience
 - `test_compute_best.py`: Deterministic price computation

## External Dependencies & Integration

### Cryptography Library
The project uses the `cryptography` package (Fernet) in `sud/security.py` for AEAD encryption; an educational stream cipher was explored but replaced by Fernet for secure defaults.

### Provider Integration
- Trip pricing aggregates data from multiple external providers. The `get_real_time_prices_secure()` function in `sud/services.py`:
- Fetches from untrusted sources
- Validates integrity via HMAC hashing
- Fails gracefully if providers unavailable
- Returns `TripOffer` list for best-price computation

## Critical Commands & Workflows

### Running Tests
```bash
python -m pytest tests/ -v
```

### Validation & Linting
No explicit build or lint commands documented—project is Python-only, minimal dependencies.

## Design Decisions & Their "Why"

1. **AEAD (Fernet)**: Use tested AEAD primitives for at-rest encryption in `sud/security.py`.
2. **Deterministic Price Logic**: Enables auditability—same inputs always produce same output, satisfying fairness requirement.
3. **Rate Limiting on Requests**: Prevents provider abuse and DoS attacks on external services.
4. **Constant-Time Password Comparison**: Mitigates timing attacks on authentication.
5. **PBKDF2 with 100k Iterations**: Slows brute-force attacks on password hashes.

## Key Files to Study First

- [README.md](README.md): Security objectives and test cases for each function
- [sud/services.py](sud/services.py): Main service functions for authentication, trip creation, provider queries, and price computation
- [sud/security.py](sud/security.py): Cryptographic helpers (PBKDF2, HMAC, Fernet AEAD)
- [sud/createuserID.py](sud/createuserID.py): User account management utilities
- [sud/providers.py](sud/providers.py): Provider clients and mock implementations

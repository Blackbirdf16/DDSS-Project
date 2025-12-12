# Copilot Instructions for DDSS-Project

## Project Overview
DDSS-Project (Security-Driven Design Specification for FairRide) is an educational security-focused ride-sharing platform implementation. The architecture follows Security-Driven Development (SDD) methodology, where security requirements drive the design of four core functions: authentication, secure trip requests, real-time pricing, and fair price computation.

## Architecture & Key Components

### Core Functions (sud/ module)
The project implements four security-driven functions as the foundation:

1. **Authentication** (`sud/auth.py`): PBKDF2-SHA256 password hashing with account lockout after 5 failed attempts
2. **Trip Security** (`sud/trip_security.py`): Encrypts trip data using SHA-256-driven stream cipher, includes rate limiting via `SlidingWindowRateLimiter`
3. **Pricing** (`sud/pricing.py`): Compares trip offers using deterministic logic (price → ETA as tiebreaker)
4. **Validation** (`sud/validation.py`): Input validation for `TripRequest` (origin, destination, battery, max_wait)

### Security Patterns Applied
- **Access Control**: Authentication before any system access (sud/auth.py)
- **Confidentiality**: Encryption of sensitive trip data (sud/trip_security.py, sud/crypto.py)
- **Integrity**: HMAC validation of price data; constant-time password comparison
- **Resilience**: Rate limiting for provider requests; graceful handling of provider failures
- **Auditability**: Deterministic price comparison and hashing of provider responses

### Cryptography Approach
The project uses a SHA-256-driven stream cipher (not Fernet) in `sud/trip_security.py` for educational purposes. Key functions:
- `_derive_key()`: HMAC-based key derivation
- `_keystream()`: Counter-mode stream generation using SHA-256
- `_encrypt_payload()` / `_decrypt_payload()`: XOR-based symmetric encryption with nonce and base64 encoding

## Development Patterns & Conventions

### Module Organization
- `sud/`: Core security utilities and functions
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
- Custom exceptions: `ValidationError` (sud/validation.py)
- Validation is defensive: all inputs checked before crypto operations
- Account lockout on failed authentication (sud/auth.py)

### Rate Limiting
The `SlidingWindowRateLimiter` class enforces per-user limits on provider requests. Constructor:
```python
SlidingWindowRateLimiter(limit=10, window_seconds=60, clock=time.time)
```

## Testing Strategy

Tests should verify three security properties per function:
1. **Positive case**: Correct inputs produce expected behavior
2. **Negative case**: Invalid/malicious inputs are rejected
3. **Security property**: Sensitive data handling (no plaintext, constant-time comparisons, audit trail)

Example test structure (from README):
- `test_auth.py`: Reject invalid credentials, verify no credential leakage in logs
- `test_trip_security.py`: Reject unauthenticated trip creation, verify encryption
- `test_pricing.py`: Verify deterministic comparison, audit trail generation
- `test_validation.py`: Malformed input rejection

## External Dependencies & Integration

### Cryptography Library
The project uses `cryptography` package (Fernet) in `sud/crypto.py` but implements custom stream cipher in `sud/trip_security.py` for educational transparency. Both approaches available—preserve this dual implementation for learning purposes.

### Provider Integration
Trip pricing aggregates data from multiple external providers. The `get_real_time_prices_from_providers()` function in `sud/trip_security.py`:
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

1. **Custom Stream Cipher**: Educational transparency over production convenience. Preserves learning of cryptographic primitives.
2. **Deterministic Price Logic**: Enables auditability—same inputs always produce same output, satisfying fairness requirement.
3. **Rate Limiting on Requests**: Prevents provider abuse and DoS attacks on external services.
4. **Constant-Time Password Comparison**: Mitigates timing attacks on authentication.
5. **PBKDF2 with 100k Iterations**: Slows brute-force attacks on password hashes.

## Key Files to Study First

- [README.md](README.md): Security objectives and test cases for each function
- [sud/auth.py](sud/auth.py): Template for secure authentication implementation
- [sud/trip_security.py](sud/trip_security.py): Complex example of layered security (encryption + rate limiting + integrity checks)
- [sud/pricing.py](sud/pricing.py): Simple, deterministic fair selection logic

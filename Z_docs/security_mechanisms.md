# Security Mechanisms for FairRideApp

This document summarizes the **security mechanisms** integrated into the FairRideApp secure development process and how they are mapped to the **STDD life cycle**.

The goal is to ensure that the four main security requirements are systematically enforced:

- **R1 – Data Protection & Privacy**
- **R2 – Secure Authentication**
- **R3 – Fair Pricing Validation**
- **R4 – Auditability & Transparency**

---

## 1. Mechanism Overview

| ID | Mechanism                     | Main Requirement(s) | Implemented In                |
|----|------------------------------|----------------------|-------------------------------|
| M1 | Application-level encryption | R1                   | `sud/crypto.py`               |
| M2 | Secure protocols (HTTPS/TLS) | R1, R2               | API gateway configuration     |
| M3 | Input validation & sanitization | R3               | `sud/validation.py`, `sud/pricing.py` |
| M4 | Authentication wrapper       | R2                   | `sud/auth.py`                 |
| M5 | Audit logs & security monitoring | R4              | `sud/trip_security.py`        |
| M6 | Automated security testing   | R1–R4 (evidence)     | `tests/` + external scanners  |

---

## 2. Mechanisms by Lifecycle Phase

### 2.1 Requirements & Design

- **Use DSM model (`dsm_model.puml`)** to:
  - Identify assets: `UserData`, `Database`, `APIGateway`, `LogSystem`.
  - Link each asset to requirements R1–R4.
  - Select appropriate patterns:
    - **Encryption**, **Secure Protocols**, **Input Validation**, **Audit Logs & Monitoring**.

- **Tropos model (`secure_tropos_model.puml`)** documents:
  - Threats: Data Breach, Unauthorized Access, Price Manipulation, DoS.
  - Mitigations: M1–M5 as countermeasures.

### 2.2 Implementation

- **M1 – Encryption (`sud/crypto.py`)**
  - Generates symmetric keys and encrypts structured trip/user data.
  - Used by pricing and trip-security modules when storing or transmitting sensitive fields.

- **M2 – Secure Protocols**
  - Assumption: all external traffic goes through an **HTTPS API gateway**.
  - Any URL in the code/API spec must be `https://` and include certificate validation on the client side (if applicable).

- **M3 – Input Validation (`sud/validation.py`, `sud/pricing.py`)**
  - Central validation functions for:
    - Trip distance, time, base fare.
    - User identifiers and tokens.
  - Rejects negative or unrealistic values before price calculation (prevents price manipulation and basic injection).

- **M4 – Authentication Wrapper (`sud/auth.py`)**
  - Verifies that a caller is authenticated before sensitive operations (e.g. price quote, booking).
  - Decouples authentication checks from business logic so they can be tested and extended.

- **M5 – Audit Logs & Monitoring (`sud/trip_security.py`)**
  - Records security-relevant events:
    - Failed authentication attempts.
    - Suspicious pricing requests.
    - Validation errors, critical exceptions.
  - Supports R4 by providing traceability for future investigations.

### 2.3 Testing & Analysis

- **M6 – Automated Security Testing**
  - **Unit tests** in `tests/` assert:
    - Encryption round-trip (encrypt/decrypt).
    - Validation rules (valid vs invalid inputs).
    - Authentication behaviour (access allowed/denied).
  - Static analysis:
    - Run tools such as `bandit` on the `sud/` package.
  - Vulnerability scanning:
    - Run a dependency scanner (e.g. `pip-audit`) on `requirements.txt`.

---

## 3. Traceability to Requirements

- **R1 – Data Protection & Privacy**
  - M1 (Encryption), M2 (Secure Protocols), M5 (Audit Logs).
- **R2 – Secure Authentication**
  - M2 (Secure Protocols), M4 (Authentication Wrapper), M5 (logging of auth failures).
- **R3 – Fair Pricing Validation**
  - M3 (Input Validation), M6 (tests that enforce pricing rules).
- **R4 – Auditability & Transparency**
  - M5 (Audit Logs & Monitoring), M6 (test evidence and scanning reports).

Each mechanism is referenced in the **STDD security activity diagram** (`stdd_security_diagram.puml`) as part of the final secure development iteration.

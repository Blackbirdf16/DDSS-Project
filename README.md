# DDSS-Project

## FairRide  Secure Price Comparison Platform

FairRide is a security-driven ride price comparison system designed to demonstrate Secure Software Development and STDD principles. The application allows users to securely authenticate, submit trip requests, retrieve real-time ride prices from external providers, and compute the best available option in a transparent and auditable way.

The system prioritizes security from design to implementation by integrating access control, encryption, integrity validation, availability safeguards, and auditability into its core functionality. Each critical operation is implemented as a dedicated _secure() function and validated through automated tests that verify both functional correctness and security properties.

FairRide is intended as an educational reference project, showcasing how threat modeling, security patterns, and testing strategies can be systematically applied throughout the software development lifecycle.

## Core Security Functions

1. uthenticate_user()  Access control + confidentiality  
2. create_trip_request_secure()  Secure data handling + encryption  
3. get_real_time_prices_secure()  Integrity + availability + resilience  
4. compute_best_price_secure()  Transparency + auditability + fairness

## Security-Driven Function Definition (SUD)

### Function 1  \uthenticate_user()\

**Objective:** Ensure that only authorized users can access the FairRide system while protecting user credentials from disclosure, misuse, or impersonation.

**Domain Knowledge:**
- Users authenticate using credentials  
- Credentials are sensitive data  
- Authentication precedes any system interaction  
- Sessions are established after successful login  

**Security Pattern:** Access Control with Confidential Credential Handling  
This pattern enforces authentication before access and protects credentials through secure handling mechanisms.

**Tests:** Reject invalid credentials, reject missing credentials, ensure credentials are never exposed in logs.

### Function 2  \create_trip_request_secure()\

**Objective:** Ensure that trip requests are created only by authenticated users and that sensitive trip data is securely handled and protected against leakage or manipulation.

**Domain Knowledge:**
- TripRequest includes origin, destination, timestamp, and userId  
- Location data is sensitive  
- Only authenticated users may create trips  
- Trip data is securely stored  

**Security Pattern:** Secure Data Handling with Encryption  
This pattern ensures that trip data is validated and encrypted to prevent unauthorized access or disclosure.

**Tests:** Reject trip creation without authentication, reject malformed input, verify encrypted storage.

### Function 3  \get_real_time_prices_secure()\

**Objective:** Ensure that real-time price data obtained from external providers is accurate, available, and protected against manipulation or service disruption.

**Domain Knowledge:**
- Prices are retrieved from multiple external providers  
- External data sources are untrusted  
- Price data must be continuously available  
- System must tolerate partial provider failures  

**Security Pattern:** Integrity and Resilient Communication Pattern  
This pattern ensures data integrity, availability, and resilience when interacting with external services.

**Tests:** Reject data failing integrity validation, ensure availability on provider failure, detect abnormal responses.

### Function 4  \compute_best_price_secure()\

**Objective:** Ensure that the best ride price is computed in a transparent, auditable, and fair manner, preventing manipulation or biased outcomes.

**Domain Knowledge:**
- Multiple validated price quotes are compared  
- Comparison logic must be deterministic  
- Results must be traceable and explainable  
- Users rely on the correctness of the result  

**Security Pattern:** Auditable Decision and Transparency Pattern  
This pattern ensures that price computation is traceable, verifiable, and free from hidden manipulation.

**Tests:** Verify identical inputs produce identical outputs, ensure auditability, detect inconsistent data.

## Implementation Status

 **Complete**: All 4 core security functions implemented and tested.  
 **All tests passing**: \python -m pytest tests/ -v\  **30 passed**  
 **Encryption**: Fernet AEAD implemented in \sud/security.py\  
 **Environment secrets**: Env-based config in \sud/config.py\  

**Key Files:** \sud/services.py\, \sud/security.py\, \sud/createuserID.py\, \sud/providers.py\

**Note:** In-memory storage (InMemoryDB, RateLimiter) is suitable for development; production deployments should use persistent stores (PostgreSQL, Redis).

## Quick Start

### Development Mode (In-Memory)

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
python -m pytest -q
```

### Production Mode (PostgreSQL + Redis)

Use Docker Compose for easy setup:

```bash
# Start PostgreSQL and Redis
docker-compose up -d

# Set environment variables
export FAIRRIDE_DB_URL="postgresql://fairride_user:fairride_dev_password@localhost:5432/fairride"
export FAIRRIDE_REDIS_URL="redis://localhost:6379/0"
export FAIRRIDE_AT_REST_KEY="<base64-encoded-key>"
export FAIRRIDE_SESSION_SECRET="<base64-encoded-secret>"
export FAIRRIDE_PROVIDER_HMAC_KEY="<base64-encoded-key>"

# Run health check
python healthcheck.py

# Initialize database
python init_db.py

# Run tests including integration
python -m pytest -q
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed production setup and [.env.example](.env.example) for environment variable configuration.

## Dependencies

See \
equirements.txt\:
- \cryptography>=41.0.0\  Fernet AEAD encryption
- \pytest>=7.0.0\  Unit testing framework

Install with: \pip install -r requirements.txt\

## Running Tests

\\\ash
python -m pytest tests/ -v
\\\

## Next Steps (Production Enhancements)

1. ✅ Replace educational cipher with AEAD (Fernet AEAD implemented)
2. ✅ Implement server-side session store (Redis implemented)
3. ✅ Move secrets to environment variables (implemented in `sud/config.py`)
4. ✅ Persist user data and rate-limiting (PostgreSQL + Redis implemented)
5. ✅ Add TLS guidance, structured audit logging with correlation IDs, CI/CD pipeline

**Optional Enhancements:**
- Automated key rotation for cryptographic secrets
- Enhanced monitoring and observability (metrics, distributed tracing)
- Load balancer integration and horizontal scaling
- Advanced threat detection and anomaly alerting

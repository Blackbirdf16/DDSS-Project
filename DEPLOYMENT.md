# Production Deployment Guide

This guide explains how to set up FairRide with PostgreSQL and Redis backends for production.

## Prerequisites

- Python 3.10+
- PostgreSQL 12+ (or PostgreSQL 14+ recommended)
- Redis 5.0+ (or Redis 6.0+ recommended)
- `pip` package manager

## Installation

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `cryptography>=41.0.0` — Fernet AEAD encryption
- `pytest>=7.0.0` — Testing framework
- `psycopg2-binary>=2.9.0` — PostgreSQL adapter
- `redis>=5.0.0` — Redis client

### 2. Set Up PostgreSQL

#### Option A: Local PostgreSQL (Development)

```bash
# macOS (via Homebrew)
brew install postgresql
brew services start postgresql

# Linux (Ubuntu/Debian)
sudo apt-get install postgresql postgresql-contrib
sudo service postgresql start

# Windows (via installer)
# Download from https://www.postgresql.org/download/windows/
```

#### Option B: PostgreSQL via Docker

```bash
docker run -d \
  --name fairride-db \
  -e POSTGRES_DB=fairride \
  -e POSTGRES_USER=fairride \
  -e POSTGRES_PASSWORD=secure_password \
  -p 5432:5432 \
  postgres:15-alpine
```

### 3. Set Up Redis

#### Option A: Local Redis (Development)

```bash
# macOS (via Homebrew)
brew install redis
brew services start redis

# Linux (Ubuntu/Debian)
sudo apt-get install redis-server
sudo service redis-server start

# Windows (via WSL or Docker)
```

#### Option B: Redis via Docker

```bash
docker run -d \
  --name fairride-redis \
  -p 6379:6379 \
  redis:7-alpine
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# PostgreSQL Configuration
FAIRRIDE_DB_URL=postgresql://fairride:secure_password@localhost:5432/fairride

# Redis Configuration
FAIRRIDE_REDIS_URL=redis://localhost:6379/0

# Security Keys (Fernet base64-encoded; use 'b64:' prefix for auto-decoding)
SECURITY_AT_REST_KEY=b64:YOUR_BASE64_ENCODED_FERNET_KEY_HERE
SECURITY_PROVIDER_HMAC_KEY=your_hmac_key_32_chars_minimum
```

### Generate Fernet Key

```python
from cryptography.fernet import Fernet

key = Fernet.generate_key().decode()
print(f"SECURITY_AT_REST_KEY=b64:{key}")
```

## Database Initialization

### Initialize PostgreSQL Schema

```bash
python init_db.py
# or with custom connection string:
python init_db.py --connection-string postgresql://user:pass@host:5432/fairride
```

This creates:
- `users` table with email, password hash, salt, and active status
- `trips` table with encrypted trip data
- Indexes for efficient lookups

### (Optional) Drop and Recreate

```bash
python init_db.py --drop-existing  # WARNING: Deletes all data
```

## Running the Application

### Development (In-Memory Database)

```bash
# Uses InMemoryDB (no persistence) and in-memory sessions
python -c "
from sud.config import SecurityConfig
from sud.services import FairRideService, InMemoryDB
from sud.createuserID import UserManager

cfg = SecurityConfig()
db = InMemoryDB()
service = FairRideService(cfg, db)
manager = UserManager(service, db, cfg)

# Create test account
success, user_id, error = manager.create_account('test@example.com', 'SecurePass123!')
print(f'Account created: {user_id}' if success else f'Error: {error}')
"
```

### Production (PostgreSQL + Redis)

```python
from sud.config import SecurityConfig
from sud.database import PostgresDB
from sud.redis_session import RedisSessionStore
from sud.services import FairRideService
from sud.createuserID import UserManager

# Initialize backends
cfg = SecurityConfig()
db = PostgresDB()  # Reads FAIRRIDE_DB_URL from environment
session_store = RedisSessionStore()  # Reads FAIRRIDE_REDIS_URL from environment

# Create service with persistent backends
service = FairRideService(cfg, db, session_store=session_store)
manager = UserManager(service, db, cfg)

# Now use manager for account operations
# Sessions are persisted in Redis with automatic expiration
# Users are stored in PostgreSQL
```

## Testing

### Run Full Test Suite

```bash
python -m pytest tests/ -v
```

All 30 tests pass with in-memory backends. To test with PostgreSQL/Redis:

```bash
# Set environment variables
export FAIRRIDE_DB_URL=postgresql://fairride:password@localhost:5432/fairride
export FAIRRIDE_REDIS_URL=redis://localhost:6379/0

# Run tests
python -m pytest tests/ -v
```

## Security Checklist

- [ ] PostgreSQL password set to strong value (avoid default)
- [ ] Redis password set if exposed to network (run with `--requirepass`)
- [ ] Environment variables securely managed (use `.env` file, not hardcoded)
- [ ] FAIRRIDE_DB_URL uses SSL connection (`postgresql://user:pass@host:5432/db?sslmode=require`)
- [ ] FAIRRIDE_REDIS_URL uses TLS if Redis is remote (`rediss://` instead of `redis://`)
- [ ] Fernet key (SECURITY_AT_REST_KEY) rotated periodically
- [ ] Database backups enabled and tested
- [ ] Application logs monitored for security events
- [ ] Rate limiting tuned for your traffic patterns (check `sud/config.py`)

## Monitoring & Maintenance

### Database Health

```sql
-- Check users table size
SELECT pg_size_pretty(pg_total_relation_size('users'));

-- Check trips table size
SELECT pg_size_pretty(pg_total_relation_size('trips'));

-- List active sessions (in Redis)
KEYS session:*

-- Monitor slow queries
log_statement = 'all'  -- in postgresql.conf
```

### Redis Health

```bash
# Check Redis info
redis-cli INFO

# Monitor commands
redis-cli MONITOR

# Check memory usage
redis-cli INFO memory
```

## Scaling Considerations

### Multi-Node Deployments

- **Database**: Use PostgreSQL replication (streaming replication or logical replication)
- **Sessions**: Redis sentinel or cluster for high availability
- **Application**: Deploy multiple instances behind a load balancer
- **Rate Limiting**: Move RateLimiter to Redis for distributed coordination

### Performance Optimization

- Add database connection pooling (PgBouncer for PostgreSQL)
- Enable Redis persistence if needed (RDB or AOF)
- Monitor slow queries and add indexes
- Consider caching frequent queries (Redis Caching)

## Troubleshooting

### PostgreSQL Connection Error

```
Error: could not connect to server
```

Solution:
- Check `FAIRRIDE_DB_URL` environment variable is set correctly
- Verify PostgreSQL is running: `pg_isready -h localhost`
- Check credentials: `psql -U fairride -d fairride -h localhost`

### Redis Connection Error

```
Error: ConnectionError: [Errno 111] Connection refused
```

Solution:
- Check `FAIRRIDE_REDIS_URL` environment variable is set correctly
- Verify Redis is running: `redis-cli ping`
- Check Redis port: `netstat -an | grep 6379`

### Database Initialization Fails

```
Solution:
- Drop existing tables: `python init_db.py --drop-existing`
- Check database privileges: User must have CREATE TABLE permissions
- Verify database exists: `psql -l | grep fairride`
```

## Next Steps

1. Configure TLS/HTTPS for API transport
2. Add structured logging and monitoring (ELK stack, CloudWatch)
3. Implement key rotation for SECURITY_AT_REST_KEY
4. Set up automated backups
5. Configure CI/CD pipeline with automated tests

## Transport Security (TLS)

FairRide is a Python library/service layer. When deploying behind a web API, ensure transport security:

- Terminate TLS at a reverse proxy (e.g., NGINX, Envoy, AWS ALB) or in your ASGI/WSGI server.
- Enforce HTTPS-only by redirecting HTTP to HTTPS and setting `Strict-Transport-Security` headers.
- If your app makes outbound HTTP calls to providers, prefer `https://` endpoints and verify certificates.
- For PostgreSQL, enable SSL by appending `?sslmode=require` to `FAIRRIDE_DB_URL` when supported by your DB setup.
- For Redis over untrusted networks, use `rediss://` (TLS) and authentication.

Example NGINX snippet enforcing HTTPS:

```nginx
server {
  listen 80;
  server_name example.com;
  return 301 https://$host$request_uri;
}

server {
  listen 443 ssl http2;
  server_name example.com;
  ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

  location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }
}
```

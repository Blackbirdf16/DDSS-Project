# FairRide Production Setup - Quick Reference

## 🚀 Quick Start

### 1. Start Backend Services
```bash
docker-compose up -d
```

### 2. Initialize Database (First Time Only)
```bash
# Windows
set FAIRRIDE_DB_URL=postgresql://fairride_user:fairride_dev_password@localhost:5433/fairride
python init_db.py

# Linux/Mac
export FAIRRIDE_DB_URL=postgresql://fairride_user:fairride_dev_password@localhost:5433/fairride
python init_db.py
```

### 3. Run Health Checks
```bash
# Windows
set FAIRRIDE_DB_URL=postgresql://fairride_user:fairride_dev_password@localhost:5433/fairride
set FAIRRIDE_REDIS_URL=redis://localhost:6379/0
python healthcheck.py

# Linux/Mac
export FAIRRIDE_DB_URL=postgresql://fairride_user:fairride_dev_password@localhost:5433/fairride
export FAIRRIDE_REDIS_URL=redis://localhost:6379/0
python healthcheck.py
```

### 4. Start the API Server

**Option A: Using startup script (Windows)**
```bash
start-production.bat
```

**Option B: Using startup script (Linux/Mac)**
```bash
chmod +x start-production.sh
./start-production.sh
```

**Option C: Manual (with environment variables)**
```bash
# Windows PowerShell
$env:FAIRRIDE_DB_URL="postgresql://fairride_user:fairride_dev_password@localhost:5433/fairride"
$env:FAIRRIDE_REDIS_URL="redis://localhost:6379/0"
$env:SECURITY_AT_REST_KEY="b64:x-6MgPr_MwMTiRMP3JR00W5n8iY_FbtINKJVX5nEbEI="
$env:SECURITY_SESSION_SECRET="b64:IOOYrLy8OGCc-unzGUgzkaNv1crFbmAzaHvxGUk9Eu0="
$env:SECURITY_PROVIDER_HMAC_KEY="e5ab990624ac28d75f78c46694f5bae0f57a0d16d5141019b3e91743f33bcfc4"
python app.py
```

## 📱 For Expo Go Connection

**Your Backend URL:** `http://192.168.1.37:8000`

Update your Expo app config:
```javascript
// src/config.js or similar
const API_BASE_URL = 'http://192.168.1.37:8000';
```

## 🧪 Testing

### Run All Tests
```bash
python -m pytest tests/ -v
```

### Run Integration Tests (with PostgreSQL + Redis)
```bash
# Windows PowerShell
$env:FAIRRIDE_DB_URL="postgresql://fairride_user:fairride_dev_password@localhost:5433/fairride"
$env:FAIRRIDE_REDIS_URL="redis://localhost:6379/0"
$env:SECURITY_AT_REST_KEY="b64:x-6MgPr_MwMTiRMP3JR00W5n8iY_FbtINKJVX5nEbEI="
$env:SECURITY_PROVIDER_HMAC_KEY="e5ab990624ac28d75f78c46694f5bae0f57a0d16d5141019b3e91743f33bcfc4"
python -m pytest tests/test_integration_backends.py -v
```

## 🐳 Docker Commands

```bash
# Start containers
docker-compose up -d

# Stop containers
docker-compose down

# View logs
docker-compose logs -f

# Restart containers
docker-compose restart

# Remove containers and volumes (WARNING: Deletes all data!)
docker-compose down -v
```

## 🔑 Environment Variables

Stored in `.env` file:

```bash
# Database
FAIRRIDE_DB_URL=postgresql://fairride_user:fairride_dev_password@localhost:5433/fairride

# Redis
FAIRRIDE_REDIS_URL=redis://localhost:6379/0

# Encryption Keys
SECURITY_AT_REST_KEY=b64:x-6MgPr_MwMTiRMP3JR00W5n8iY_FbtINKJVX5nEbEI=
SECURITY_SESSION_SECRET=b64:IOOYrLy8OGCc-unzGUgzkaNv1crFbmAzaHvxGUk9Eu0=
SECURITY_PROVIDER_HMAC_KEY=e5ab990624ac28d75f78c46694f5bae0f57a0d16d5141019b3e91743f33bcfc4
```

## 🌐 API Endpoints

- **Base URL:** `http://192.168.1.37:8000`
- **API Docs:** `http://192.168.1.37:8000/docs`
- **Health Check:** `http://192.168.1.37:8000/health`

## ✅ Production vs Development Mode

| Feature | Development | Production |
|---------|-------------|------------|
| Database | In-Memory | PostgreSQL |
| Sessions | In-Memory | Redis |
| Encryption | ✅ | ✅ |
| Rate Limiting | In-Memory | Redis-backed |
| Persistence | ❌ | ✅ |

## 🔧 Troubleshooting

**Container not starting?**
```bash
docker-compose logs postgres
docker-compose logs redis
```

**Connection refused?**
- Check if containers are running: `docker ps`
- Verify port mappings: PostgreSQL (5433), Redis (6379)
- Check firewall settings

**Database schema issues?**
```bash
# Re-initialize database (WARNING: Clears all data!)
python init_db.py --drop-existing
```

**Tests failing?**
- Ensure environment variables are set
- Run health checks first: `python healthcheck.py`
- Check Docker containers are running

## 📊 Current Status

✅ PostgreSQL running on `localhost:5433`
✅ Redis running on `localhost:6379`  
✅ Database schema initialized
✅ Health checks passing
✅ Integration tests passing
✅ Environment variables configured
✅ Encryption keys generated

**Ready for production use!** 🎉

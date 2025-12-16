#!/usr/bin/env python3
"""Health check utility for FairRide backend services.

Verifies connectivity to PostgreSQL and Redis before starting the application.
Exits with status 0 if all checks pass, 1 otherwise.
"""
import os
import sys
import time


def check_postgres() -> bool:
    """Check PostgreSQL connectivity."""
    db_url = os.getenv("FAIRRIDE_DB_URL")
    if not db_url:
        print("⚠️  FAIRRIDE_DB_URL not set (development mode - using in-memory DB)")
        return True

    try:
        import psycopg2
        conn = psycopg2.connect(db_url)
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        if result == (1,):
            print("✅ PostgreSQL connection successful")
            return True
        else:
            print("❌ PostgreSQL query returned unexpected result")
            return False
    except ImportError:
        print("❌ psycopg2-binary not installed")
        return False
    except Exception as e:
        print(f"❌ PostgreSQL connection failed: {e}")
        return False


def check_redis() -> bool:
    """Check Redis connectivity."""
    redis_url = os.getenv("FAIRRIDE_REDIS_URL")
    if not redis_url:
        print("⚠️  FAIRRIDE_REDIS_URL not set (development mode - using in-memory sessions)")
        return True

    try:
        import redis
        r = redis.from_url(redis_url)
        r.ping()
        print("✅ Redis connection successful")
        return True
    except ImportError:
        print("❌ redis package not installed")
        return False
    except Exception as e:
        print(f"❌ Redis connection failed: {e}")
        return False


def main():
    """Run all health checks."""
    print("🔍 FairRide Backend Health Check\n")
    
    checks = [
        ("PostgreSQL", check_postgres),
        ("Redis", check_redis),
    ]
    
    results = []
    for name, check_fn in checks:
        print(f"Checking {name}...")
        result = check_fn()
        results.append(result)
        print()
    
    if all(results):
        print("✅ All health checks passed")
        return 0
    else:
        print("❌ Some health checks failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())

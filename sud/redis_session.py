"""Redis-backed session store for FairRide.

Provides distributed session management with token revocation support.
Supports login sessions with automatic expiration and logout revocation.
"""

from typing import Optional
import os
import time


class RedisSessionStore:
    """Redis-backed persistent session store with revocation support."""

    def __init__(self, redis_url: Optional[str] = None, client: Optional[object] = None) -> None:
        """Initialize Redis connection for session storage.

        Args:
            redis_url: Redis connection URL.
                      Defaults to env var FAIRRIDE_REDIS_URL.
                      Format: redis://localhost:6379/0
        """
        if redis_url is None:
            redis_url = os.getenv("FAIRRIDE_REDIS_URL", "redis://localhost:6379/0")

        self.redis_url = redis_url
        self.redis_client = client
        if self.redis_client is None:
            self._init_connection()

    def _init_connection(self) -> None:
        """Initialize Redis connection."""
        try:
            import redis
            self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
            # Test connection
            self.redis_client.ping()
        except ImportError:
            raise ImportError("redis required for Redis session support. Install: pip install redis")
        except Exception as e:
            raise RuntimeError(f"Failed to connect to Redis: {e}")

    def store_session(self, token: str, user_id: str, ttl_seconds: int) -> None:
        """Store a session token in Redis.

        Args:
            token: Session token (opaque string)
            user_id: Associated user ID
            ttl_seconds: Time-to-live in seconds (expiration)
        """
        try:
            session_key = f"session:{token}"
            self.redis_client.setex(session_key, ttl_seconds, user_id)
        except Exception as e:
            raise RuntimeError(f"Failed to store session: {e}")

    def get_session(self, token: str) -> Optional[str]:
        """Retrieve a user ID from a valid session token.

        Args:
            token: Session token

        Returns:
            user_id if token is valid and not revoked, None otherwise
        """
        try:
            # Check if token is revoked
            if self.redis_client.exists(f"revoked:{token}"):
                return None

            # Get user_id from session
            user_id = self.redis_client.get(f"session:{token}")
            return user_id
        except Exception as e:
            raise RuntimeError(f"Failed to get session: {e}")

    def revoke_session(self, token: str, ttl_seconds: int = 86400) -> None:
        """Revoke a session token (logout).

        Adds token to revocation list for the duration of its original TTL,
        ensuring revoked tokens cannot be reused even if they're still in memory.

        Args:
            token: Session token to revoke
            ttl_seconds: How long to keep the revocation record (default 1 day)
        """
        try:
            revoke_key = f"revoked:{token}"
            self.redis_client.setex(revoke_key, ttl_seconds, "1")
        except Exception as e:
            raise RuntimeError(f"Failed to revoke session: {e}")

    def revoke_all_user_sessions(self, user_id: str) -> None:
        """Revoke all active sessions for a user (force logout everywhere).

        Args:
            user_id: User ID whose sessions to revoke
        """
        try:
            # Scan for all sessions belonging to this user
            pattern = "session:*"
            cursor = "0"
            while True:
                cursor, keys = self.redis_client.scan(cursor, match=pattern, count=100)
                for key in keys:
                    stored_user_id = self.redis_client.get(key)
                    if stored_user_id == user_id:
                        # Extract token from key and revoke it
                        token = key.replace("session:", "")
                        self.revoke_session(token)

                if cursor == "0":
                    break
        except Exception as e:
            raise RuntimeError(f"Failed to revoke all user sessions: {e}")

    def is_session_valid(self, token: str) -> bool:
        """Check if a session token is valid and not revoked.

        Args:
            token: Session token

        Returns:
            True if session is valid, False if revoked or expired
        """
        try:
            if self.redis_client.exists(f"revoked:{token}"):
                return False
            return self.redis_client.exists(f"session:{token}") > 0
        except Exception as e:
            raise RuntimeError(f"Failed to check session validity: {e}")

    def delete_session(self, token: str) -> None:
        """Explicitly delete a session (logout without revocation).

        Args:
            token: Session token
        """
        try:
            self.redis_client.delete(f"session:{token}")
        except Exception as e:
            raise RuntimeError(f"Failed to delete session: {e}")

    def close(self) -> None:
        """Close Redis connection."""
        if hasattr(self, 'redis_client'):
            self.redis_client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

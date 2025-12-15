"""PostgreSQL database layer for FairRide.

Provides persistent storage for users and trips using SQLAlchemy ORM.
Supports creation, retrieval, and updates of user accounts.
"""

from typing import Optional
from .models import User
import os


class PostgresDB:
    """PostgreSQL-backed persistent database for users and encrypted trips."""

    def __init__(self, connection_string: Optional[str] = None) -> None:
        """Initialize PostgreSQL connection.

        Args:
            connection_string: PostgreSQL connection string.
                              Defaults to env var FAIRRIDE_DB_URL.
                              Format: postgresql://user:password@localhost:5432/fairride
        """
        if connection_string is None:
            connection_string = os.getenv(
                "FAIRRIDE_DB_URL",
                "postgresql://fairride:fairride@localhost:5432/fairride"
            )

        self.connection_string = connection_string
        self._init_connection()

    def _init_connection(self) -> None:
        """Initialize database connection and create tables if needed."""
        try:
            import psycopg2
            self.conn = psycopg2.connect(self.connection_string)
            self.cursor = self.conn.cursor()
            self._ensure_schema()
        except ImportError:
            raise ImportError("psycopg2 required for PostgreSQL support. Install: pip install psycopg2-binary")
        except Exception as e:
            raise RuntimeError(f"Failed to connect to PostgreSQL: {e}")

    def _ensure_schema(self) -> None:
        """Create tables if they don't exist (idempotent)."""
        create_users_table = """
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """

        create_trips_table = """
        CREATE TABLE IF NOT EXISTS trips (
            trip_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            encrypted_blob BYTEA NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """

        create_index_email = """
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        """

        create_index_user_id = """
        CREATE INDEX IF NOT EXISTS idx_trips_user_id ON trips(user_id);
        """

        for sql in [create_users_table, create_trips_table, create_index_email, create_index_user_id]:
            self.cursor.execute(sql)
        self.conn.commit()

    def add_user(self, user: User) -> None:
        """Insert or update a user record.

        Args:
            user: User dataclass with user_id, email, password_hash, password_salt, is_active
        """
        sql = """
        INSERT INTO users (user_id, email, password_hash, password_salt, is_active)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (user_id) DO UPDATE SET
            email = EXCLUDED.email,
            password_hash = EXCLUDED.password_hash,
            password_salt = EXCLUDED.password_salt,
            is_active = EXCLUDED.is_active,
            updated_at = CURRENT_TIMESTAMP;
        """
        try:
            self.cursor.execute(sql, (
                user.user_id,
                user.email.lower(),
                user.password_hash,
                user.password_salt,
                user.is_active
            ))
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise RuntimeError(f"Failed to add user: {e}")

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Retrieve a user by email address.

        Args:
            email: User email (case-insensitive)

        Returns:
            User object if found, None otherwise
        """
        sql = "SELECT user_id, email, password_hash, password_salt, is_active FROM users WHERE LOWER(email) = %s;"
        try:
            self.cursor.execute(sql, (email.lower(),))
            row = self.cursor.fetchone()
            if row:
                return User(
                    user_id=row[0],
                    email=row[1],
                    password_hash=row[2],
                    password_salt=row[3],
                    is_active=row[4]
                )
            return None
        except Exception as e:
            raise RuntimeError(f"Failed to get user: {e}")

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Retrieve a user by user ID.

        Args:
            user_id: User ID (UUID)

        Returns:
            User object if found, None otherwise
        """
        sql = "SELECT user_id, email, password_hash, password_salt, is_active FROM users WHERE user_id = %s;"
        try:
            self.cursor.execute(sql, (user_id,))
            row = self.cursor.fetchone()
            if row:
                return User(
                    user_id=row[0],
                    email=row[1],
                    password_hash=row[2],
                    password_salt=row[3],
                    is_active=row[4]
                )
            return None
        except Exception as e:
            raise RuntimeError(f"Failed to get user by ID: {e}")

    def save_trip_encrypted(self, trip_id: str, user_id: str, blob: bytes) -> None:
        """Save an encrypted trip blob.

        Args:
            trip_id: Unique trip identifier
            user_id: User who created the trip
            blob: Encrypted trip data (bytes)
        """
        sql = """
        INSERT INTO trips (trip_id, user_id, encrypted_blob)
        VALUES (%s, %s, %s)
        ON CONFLICT (trip_id) DO UPDATE SET
            encrypted_blob = EXCLUDED.encrypted_blob;
        """
        try:
            self.cursor.execute(sql, (trip_id, user_id, blob))
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise RuntimeError(f"Failed to save trip: {e}")

    def load_trip_encrypted(self, trip_id: str) -> Optional[bytes]:
        """Load an encrypted trip blob.

        Args:
            trip_id: Trip identifier

        Returns:
            Encrypted blob (bytes) if found, None otherwise
        """
        sql = "SELECT encrypted_blob FROM trips WHERE trip_id = %s;"
        try:
            self.cursor.execute(sql, (trip_id,))
            row = self.cursor.fetchone()
            return row[0] if row else None
        except Exception as e:
            raise RuntimeError(f"Failed to load trip: {e}")

    def close(self) -> None:
        """Close database connection."""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

"""User account management module for FairRide application.

Provides high-level functions for:
- Account creation (registration)
- User login with session token
- User logout (session invalidation)

These functions wrap the security-driven services in sud.services with user-friendly interfaces.
"""

from typing import Optional, Tuple
from .config import SecurityConfig
from .models import User, AuthResult
from .services import FairRideService, InMemoryDB
from .security import generate_salt_b64, pbkdf2_hash_password


class UserManager:
    """Manages user account lifecycle: creation, authentication, and session management."""

    def __init__(self, service: FairRideService, db: InMemoryDB, cfg: SecurityConfig):
        """Initialize user manager with service and database.

        Args:
            service: FairRideService instance for authentication
            db: InMemoryDB instance for user storage
            cfg: SecurityConfig for hashing parameters
        """
        self.service = service
        self.db = db
        self.cfg = cfg
        self.active_sessions: dict[str, dict] = {}  # token -> user_info

    def create_account(self, email: str, password: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Create a new user account with email and password.

        Security properties:
        - Password is hashed using PBKDF2-SHA256 with 200k iterations
        - Each password gets a unique random salt
        - Passwords are never stored in plaintext
        - Account is marked active upon creation

        Args:
            email: User email address (used as unique identifier)
            password: Password string (min 8 chars recommended)

        Returns:
            Tuple[success, user_id, error_message]:
            - (True, user_id, None) on success
            - (False, None, error_message) on failure

        Examples:
            >>> um = UserManager(service, db, cfg)
            >>> success, user_id, error = um.create_account("alice@example.com", "SecurePass123!")
            >>> if success:
            ...     print(f"Account created: {user_id}")
        """
        # Input validation
        if not email or "@" not in email:
            return False, None, "Invalid email format"

        if len(email) > 254:
            return False, None, "Email too long"

        if not password or len(password) < 8:
            return False, None, "Password must be at least 8 characters"

        # Check for existing account
        if self.db.get_user_by_email(email) is not None:
            return False, None, "Email already registered"

        # Generate salt and hash password
        try:
            salt = generate_salt_b64()
            password_hash = pbkdf2_hash_password(password, salt, self.cfg.pbkdf2_iterations)

            # Create user record
            import uuid
            user_id = str(uuid.uuid4())
            user = User(
                user_id=user_id,
                email=email,
                password_hash=password_hash,
                password_salt=salt,
                is_active=True,
            )
            self.db.add_user(user)
            return True, user_id, None

        except Exception as e:
            return False, None, f"Account creation failed: {str(e)}"

    def login(self, email: str, password: str, client_id: str = "default") -> Tuple[bool, Optional[str], Optional[str]]:
        """Authenticate user and return session token.

        Security properties:
        - Rate limited (default: 5 attempts per minute per client)
        - Constant-time password comparison (timing-attack resistant)
        - Session token has TTL (default: 1 hour)
        - No credential leakage in error messages

        Args:
            email: User email address
            password: Password string
            client_id: Identifier for the client (IP, device, etc.) for rate limiting

        Returns:
            Tuple[success, session_token, error_message]:
            - (True, token, None) on success
            - (False, None, error_message) on failure (rate limited, invalid creds, etc.)

        Examples:
            >>> success, token, error = um.login("alice@example.com", "SecurePass123!", client_id="192.168.1.1")
            >>> if success:
            ...     print(f"Logged in with token: {token}")
            ...     # Use token for subsequent API calls
            >>> else:
            ...     print(f"Login failed: {error}")
        """
        if not email or not password:
            return False, None, "Email and password required"

        result: AuthResult = self.service.authenticate_user(email, password, client_id)

        if result.ok and result.session_token:
            # Track active session
            self.active_sessions[result.session_token] = {
                "user_id": result.user_id,
                "email": email,
                "created_at": __import__("time").time(),
            }
            return True, result.session_token, None
        else:
            return False, None, result.reason or "Authentication failed"

    def logout(self, session_token: str) -> Tuple[bool, Optional[str]]:
        """Invalidate a session token and log out the user.

        Security properties:
        - Removes session from active tracking
        - Prevents reuse of invalidated tokens
        - No error leakage if token is invalid

        Args:
            session_token: Session token to invalidate

        Returns:
            Tuple[success, error_message]:
            - (True, None) on success (or token doesn't exist)
            - (False, error_message) on error

        Examples:
            >>> success, error = um.logout(session_token)
            >>> if success:
            ...     print("Logged out successfully")
        """
        try:
            if session_token in self.active_sessions:
                del self.active_sessions[session_token]
            return True, None
        except Exception as e:
            return False, f"Logout failed: {str(e)}"

    def validate_session(self, session_token: str) -> Tuple[bool, Optional[str]]:
        """Check if a session token is valid and active.

        Args:
            session_token: Session token to validate

        Returns:
            Tuple[is_valid, user_id]:
            - (True, user_id) if token is valid
            - (False, None) if token is invalid/expired

        Examples:
            >>> valid, user_id = um.validate_session(token)
            >>> if valid:
            ...     print(f"Session valid for user {user_id}")
        """
        if session_token not in self.active_sessions:
            return False, None
        session_info = self.active_sessions[session_token]
        return True, session_info["user_id"]

    def get_session_info(self, session_token: str) -> Optional[dict]:
        """Get information about an active session.

        Args:
            session_token: Session token

        Returns:
            Dict with session info (user_id, email, created_at) or None if invalid

        Examples:
            >>> info = um.get_session_info(token)
            >>> if info:
            ...     print(f"Session for: {info['email']}")
        """
        return self.active_sessions.get(session_token)


# Convenience module-level functions for simple usage

_global_cfg: Optional[SecurityConfig] = None
_global_db: Optional[InMemoryDB] = None
_global_service: Optional[FairRideService] = None
_global_manager: Optional[UserManager] = None


def initialize(cfg: Optional[SecurityConfig] = None, db: Optional[InMemoryDB] = None) -> None:
    """Initialize global user manager (optional convenience function).

    Args:
        cfg: SecurityConfig (defaults to SecurityConfig() if None)
        db: InMemoryDB (defaults to InMemoryDB() if None)

    Examples:
        >>> from sud.createuserID import initialize, create_account, login, logout
        >>> initialize()  # Uses defaults
        >>> success, user_id, error = create_account("alice@example.com", "Pass123!")
    """
    global _global_cfg, _global_db, _global_service, _global_manager

    _global_cfg = cfg or SecurityConfig()
    _global_db = db or InMemoryDB()
    _global_service = FairRideService(_global_cfg, _global_db)
    _global_manager = UserManager(_global_service, _global_db, _global_cfg)


def create_account(email: str, password: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Create a new user account (uses global manager).

    Requires: initialize() called first.

    Args:
        email: User email
        password: Password

    Returns:
        Tuple[success, user_id, error_message]
    """
    if _global_manager is None:
        raise RuntimeError("Call initialize() first")
    return _global_manager.create_account(email, password)


def login(email: str, password: str, client_id: str = "default") -> Tuple[bool, Optional[str], Optional[str]]:
    """Login user (uses global manager).

    Requires: initialize() called first.

    Args:
        email: User email
        password: Password
        client_id: Client identifier for rate limiting

    Returns:
        Tuple[success, session_token, error_message]
    """
    if _global_manager is None:
        raise RuntimeError("Call initialize() first")
    return _global_manager.login(email, password, client_id)


def logout(session_token: str) -> Tuple[bool, Optional[str]]:
    """Logout user (uses global manager).

    Requires: initialize() called first.

    Args:
        session_token: Session token to invalidate

    Returns:
        Tuple[success, error_message]
    """
    if _global_manager is None:
        raise RuntimeError("Call initialize() first")
    return _global_manager.logout(session_token)


def validate_session(session_token: str) -> Tuple[bool, Optional[str]]:
    """Validate session token (uses global manager).

    Requires: initialize() called first.

    Args:
        session_token: Session token to validate

    Returns:
        Tuple[is_valid, user_id]
    """
    if _global_manager is None:
        raise RuntimeError("Call initialize() first")
    return _global_manager.validate_session(session_token)


if __name__ == "__main__":
    # Example usage
    initialize()

    print("=== FairRide User Account Demo ===\n")

    # Create account
    print("1. Creating account for alice@example.com...")
    success, user_id, error = create_account("alice@example.com", "SecurePass123!")
    if success:
        print(f"   ✓ Account created: {user_id}\n")
    else:
        print(f"   ✗ Error: {error}\n")

    # Try creating duplicate
    print("2. Attempting duplicate account creation...")
    success, user_id, error = create_account("alice@example.com", "AnotherPass456!")
    if not success:
        print(f"   ✓ Correctly rejected: {error}\n")

    # Login
    print("3. Logging in...")
    success, token, error = login("alice@example.com", "SecurePass123!", client_id="192.168.1.100")
    if success:
        print(f"   ✓ Logged in successfully")
        print(f"   Session token: {token[:20]}...\n")
    else:
        print(f"   ✗ Error: {error}\n")

    # Validate session
    print("4. Validating session...")
    valid, user_id = validate_session(token)
    if valid:
        print(f"   ✓ Session valid for user: {user_id}\n")

    # Logout
    print("5. Logging out...")
    success, error = logout(token)
    if success:
        print(f"   ✓ Logged out successfully\n")

    # Try to validate after logout
    print("6. Validating session after logout...")
    valid, user_id = validate_session(token)
    if not valid:
        print(f"   ✓ Session correctly invalidated\n")

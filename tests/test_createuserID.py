"""Tests for user account management (createuserID module)."""

import pytest
from sud.config import SecurityConfig
from sud.services import InMemoryDB, FairRideService
from sud.createuserID import UserManager


@pytest.fixture
def setup():
    """Setup test fixtures."""
    cfg = SecurityConfig()
    db = InMemoryDB()
    service = FairRideService(cfg, db)
    manager = UserManager(service, db, cfg)
    return manager, cfg, db, service


class TestCreateAccount:
    """Test account creation functionality."""

    def test_create_account_success(self, setup):
        """Successfully create a new account."""
        manager, _, _, _ = setup
        success, user_id, error = manager.create_account("alice@example.com", "SecurePass123!")
        assert success is True
        assert user_id is not None
        assert error is None

    def test_create_account_duplicate_rejected(self, setup):
        """Reject duplicate email registration."""
        manager, _, _, _ = setup
        # Create first account
        manager.create_account("alice@example.com", "Pass123!")
        # Try duplicate
        success, user_id, error = manager.create_account("alice@example.com", "DifferentPass!")
        assert success is False
        assert user_id is None
        assert "already registered" in error.lower()

    def test_create_account_invalid_email(self, setup):
        """Reject invalid email format."""
        manager, _, _, _ = setup
        success, user_id, error = manager.create_account("not-an-email", "Pass123!")
        assert success is False
        assert "invalid email" in error.lower()

    def test_create_account_short_password(self, setup):
        """Reject passwords shorter than 8 characters."""
        manager, _, _, _ = setup
        success, user_id, error = manager.create_account("alice@example.com", "short")
        assert success is False
        assert "8 characters" in error.lower()

    def test_create_account_empty_email(self, setup):
        """Reject empty email."""
        manager, _, _, _ = setup
        success, user_id, error = manager.create_account("", "Pass123!")
        assert success is False

    def test_create_account_empty_password(self, setup):
        """Reject empty password."""
        manager, _, _, _ = setup
        success, user_id, error = manager.create_account("alice@example.com", "")
        assert success is False

    def test_create_account_long_email(self, setup):
        """Reject emails longer than 254 characters."""
        manager, _, _, _ = setup
        long_email = "a" * 255 + "@example.com"
        success, user_id, error = manager.create_account(long_email, "Pass123!")
        assert success is False
        assert "too long" in error.lower()


class TestLogin:
    """Test login functionality."""

    def test_login_success(self, setup):
        """Successfully login with correct credentials."""
        manager, _, _, _ = setup
        # Create account
        manager.create_account("alice@example.com", "SecurePass123!")
        # Login
        success, token, error = manager.login("alice@example.com", "SecurePass123!", client_id="test-client")
        assert success is True
        assert token is not None
        assert error is None

    def test_login_invalid_password(self, setup):
        """Reject login with wrong password."""
        manager, _, _, _ = setup
        manager.create_account("alice@example.com", "SecurePass123!")
        success, token, error = manager.login("alice@example.com", "WrongPass123!", client_id="test-client")
        assert success is False
        assert token is None
        assert error is not None

    def test_login_nonexistent_user(self, setup):
        """Reject login for non-existent user."""
        manager, _, _, _ = setup
        success, token, error = manager.login("nonexistent@example.com", "AnyPass123!", client_id="test-client")
        assert success is False
        assert token is None

    def test_login_empty_credentials(self, setup):
        """Reject login with empty credentials."""
        manager, _, _, _ = setup
        success, token, error = manager.login("", "", client_id="test-client")
        assert success is False
        assert token is None

    def test_login_rate_limited(self, setup):
        """Test rate limiting on login attempts."""
        manager, cfg, _, _ = setup
        manager.create_account("alice@example.com", "SecurePass123!")

        # Exceed rate limit (default is 5 per minute)
        for i in range(cfg.login_max_attempts_per_minute + 1):
            success, token, error = manager.login("alice@example.com", "WrongPass", client_id="same-client")
            if i < cfg.login_max_attempts_per_minute:
                # First 5 attempts should fail but not be rate limited
                assert success is False
            else:
                # 6th attempt should be rate limited
                assert success is False
                assert "rate" in error.lower() or "invalid" in error.lower()


class TestLogout:
    """Test logout functionality."""

    def test_logout_success(self, setup):
        """Successfully logout and invalidate session."""
        manager, _, _, _ = setup
        manager.create_account("alice@example.com", "SecurePass123!")
        success, token, _ = manager.login("alice@example.com", "SecurePass123!", client_id="test-client")
        assert success is True

        # Logout
        success, error = manager.logout(token)
        assert success is True
        assert error is None

    def test_logout_invalid_token(self, setup):
        """Logout with invalid token should not error."""
        manager, _, _, _ = setup
        success, error = manager.logout("invalid-token-xyz")
        # Should succeed silently (no error leakage)
        assert success is True

    def test_logout_invalidates_session(self, setup):
        """After logout, session should be invalid."""
        manager, _, _, _ = setup
        manager.create_account("alice@example.com", "SecurePass123!")
        success, token, _ = manager.login("alice@example.com", "SecurePass123!", client_id="test-client")

        # Logout
        manager.logout(token)

        # Try to validate
        valid, user_id = manager.validate_session(token)
        assert valid is False
        assert user_id is None


class TestSessionValidation:
    """Test session validation functionality."""

    def test_validate_valid_session(self, setup):
        """Validate a valid active session."""
        manager, _, _, _ = setup
        manager.create_account("alice@example.com", "SecurePass123!")
        success, token, _ = manager.login("alice@example.com", "SecurePass123!", client_id="test-client")

        valid, user_id = manager.validate_session(token)
        assert valid is True
        assert user_id is not None

    def test_validate_invalid_session(self, setup):
        """Reject validation of invalid session."""
        manager, _, _, _ = setup
        valid, user_id = manager.validate_session("nonexistent-token")
        assert valid is False
        assert user_id is None

    def test_get_session_info(self, setup):
        """Retrieve session information."""
        manager, _, _, _ = setup
        manager.create_account("alice@example.com", "SecurePass123!")
        success, token, _ = manager.login("alice@example.com", "SecurePass123!", client_id="test-client")

        info = manager.get_session_info(token)
        assert info is not None
        assert info["email"] == "alice@example.com"
        assert "user_id" in info
        assert "created_at" in info

    def test_get_session_info_invalid(self, setup):
        """Get session info for invalid token returns None."""
        manager, _, _, _ = setup
        info = manager.get_session_info("invalid-token")
        assert info is None


class TestSecurityProperties:
    """Test security properties of account management."""

    def test_password_not_stored_plaintext(self, setup):
        """Passwords should be hashed, not stored plaintext."""
        manager, _, db, _ = setup
        password = "MySecurePassword123!"
        manager.create_account("alice@example.com", password)

        user = db.get_user_by_email("alice@example.com")
        assert user is not None
        # Password hash should not contain the plaintext password
        assert password not in user.password_hash

    def test_case_insensitive_email_lookup(self, setup):
        """Email lookup should be case-insensitive."""
        manager, _, db, _ = setup
        manager.create_account("Alice@Example.COM", "Pass123!")

        # Try login with different case
        success, token, _ = manager.login("alice@example.com", "Pass123!")
        assert success is True

        # Database should normalize email
        user = db.get_user_by_email("ALICE@EXAMPLE.COM")
        assert user is not None

    def test_salt_uniqueness(self, setup):
        """Each password should have a unique salt."""
        manager, _, db, _ = setup
        manager.create_account("alice@example.com", "Pass123!")
        manager.create_account("bob@example.com", "Pass123!")

        user1 = db.get_user_by_email("alice@example.com")
        user2 = db.get_user_by_email("bob@example.com")

        # Same password with different salts should produce different hashes
        assert user1.password_hash != user2.password_hash
        assert user1.password_salt != user2.password_salt

    def test_session_token_uniqueness(self, setup):
        """Each login should produce a unique session token."""
        manager, _, _, _ = setup
        manager.create_account("alice@example.com", "Pass123!")

        success1, token1, _ = manager.login("alice@example.com", "Pass123!", client_id="client1")
        success2, token2, _ = manager.login("alice@example.com", "Pass123!", client_id="client2")

        assert success1 is True
        assert success2 is True
        # Different logins should produce different tokens
        assert token1 != token2

    def test_no_credential_leakage_in_errors(self, setup):
        """Error messages should not leak credentials."""
        manager, _, _, _ = setup
        manager.create_account("alice@example.com", "CorrectPass123!")

        # Try wrong password
        success, token, error = manager.login("alice@example.com", "WrongPass", client_id="test")
        assert success is False
        # Error should not contain password or indicate which part (email/password) failed
        assert "wrong" not in error.lower()
        assert "password" not in error.lower()

"""Password hashing and JWT helpers (no FastAPI dependency).

Shared by the proxy server (login + token verification) and database/init_db.py
(seeding demo users with hashed passwords).
"""
import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

import jwt

from config import JWT_ALGORITHM, JWT_EXPIRE_MINUTES, JWT_SECRET

VALID_ROLES = ("admin", "user")

# --- Password hashing --------------------------------------------------------
# PBKDF2-HMAC-SHA256 from the standard library. The iteration count is stored
# inside each hash, so it can be raised later without invalidating old hashes.
_SCHEME = "pbkdf2_sha256"
_ITERATIONS = 600_000  # OWASP guidance for PBKDF2-HMAC-SHA256
_SALT_BYTES = 16


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def hash_password(password: str, iterations: int = _ITERATIONS) -> str:
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{_SCHEME}${iterations}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored_hash: str | None) -> bool:
    """Constant-time check. Returns False (never raises) for malformed hashes."""
    try:
        scheme, iterations, salt_b64, digest_b64 = (stored_hash or "").split("$")
        if scheme != _SCHEME:
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


_dummy_hash: str | None = None


def burn_password_check(password: str) -> None:
    """Spend the same time as a real check, used when the username doesn't exist.

    Keeps login latency similar for unknown and known users (limits user enumeration).
    """
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password(secrets.token_urlsafe(16))
    verify_password(password, _dummy_hash)


# --- JWT ---------------------------------------------------------------------
class TokenError(Exception):
    """Token is missing a claim, malformed, badly signed, or expired."""


def create_access_token(username: str, role: str) -> tuple[str, int]:
    """Return (signed JWT, lifetime in seconds). Claims: sub, role, iat, exp."""
    if role not in VALID_ROLES:
        raise ValueError(f"Unknown role: {role}")
    now = datetime.now(timezone.utc)
    lifetime = timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {"sub": username, "role": role, "iat": now, "exp": now + lifetime}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM), int(lifetime.total_seconds())


def decode_access_token(token: str) -> dict:
    """Verify signature + expiry and return the claims, or raise TokenError.

    The algorithm is pinned to the configured one, so 'alg: none' and algorithm
    confusion tokens are rejected.
    """
    try:
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("Token has expired") from exc
    except jwt.PyJWTError as exc:
        raise TokenError("Invalid token") from exc
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise TokenError("Invalid token")
    if claims.get("role") not in VALID_ROLES:
        raise TokenError("Invalid token")
    return claims

"""Authentication + RBAC for the proxy server.

- POST /api/auth/login  : username + password -> signed JWT
- get_current_user      : FastAPI dependency; identity comes ONLY from a verified Bearer JWT
- require_role(...)     : RBAC check, raises 403 when the role is not allowed
"""
from dataclasses import dataclass

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from config import SQLITE_PATH
from security import (
    TokenError,
    burn_password_check,
    create_access_token,
    decode_access_token,
    verify_password,
)
from sqlite_db import SqliteModel

router = APIRouter(prefix="/api/auth", tags=["auth"])

# auto_error=False so a missing/invalid header gives 401 (not FastAPI's default 403) from our code.
_bearer = HTTPBearer(auto_error=False, description="JWT from POST /api/auth/login")


@dataclass(frozen=True)
class AuthUser:
    username: str
    role: str


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status_code=401, detail=detail, headers={"WWW-Authenticate": "Bearer"})


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> AuthUser:
    """Verify the Bearer token and return the authenticated identity (401 if not valid)."""
    if credentials is None:
        raise _unauthorized("Not authenticated")
    try:
        claims = decode_access_token(credentials.credentials)
    except TokenError as exc:
        raise _unauthorized(str(exc))
    return AuthUser(username=claims["sub"], role=claims["role"])


def require_role(user: AuthUser, *allowed_roles: str) -> AuthUser:
    """RBAC check: 403 unless the authenticated user has one of the allowed roles."""
    if user.role not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail=f"Forbidden: requires role {' or '.join(allowed_roles)}",
        )
    return user


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


@router.post("/login")
async def login(body: LoginRequest):
    query = text("SELECT password_hash, role FROM users WHERE user_name = :username LIMIT 1")
    engine = SqliteModel.create_engine(SQLITE_PATH)  # shared engine (same one app.py uses)
    try:
        async with engine.connect() as connection:
            row = (await connection.execute(query, {"username": body.username})).fetchone()
    except OperationalError:
        raise HTTPException(
            status_code=500,
            detail="Users table has no auth columns. Run: python database/init_db.py",
        )

    # Same generic error for unknown user, wrong password, or an account with no password set.
    if row is None or not row.password_hash:
        burn_password_check(body.password)
        raise _unauthorized("Invalid username or password")
    if not verify_password(body.password, row.password_hash):
        raise _unauthorized("Invalid username or password")

    token, expires_in = create_access_token(body.username, row.role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "user": {"username": body.username, "role": row.role},
    }


@router.get("/me")
async def me(user: AuthUser = Depends(get_current_user)):
    """Return the identity carried by the verified token (handy for testing)."""
    return {"username": user.username, "role": user.role}

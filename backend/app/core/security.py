"""
core/security.py
=================
Password hashing and JWT issuing/verification.

WHY THIS LIVES IN core/, NOT services/:
- This is cross-cutting infrastructure (like config or exceptions),
  not a business-logic service that talks to Neo4j/Qdrant.
- Route handlers and dependencies both need it directly.

DESIGN NOTES (for interview explanation):
- Passwords are hashed with bcrypt via passlib. We NEVER store or log
  plaintext passwords. bcrypt is slow-by-design (a work factor), which
  is exactly what you want for password hashing — it makes brute-force
  attacks expensive. This is different from a fast hash like SHA-256,
  which is wrong for passwords precisely because it's fast.
- JWTs are signed (not encrypted) with HS256 using SECRET_KEY. Anyone
  can decode the payload, but only the server can produce a valid
  signature — so the client can't forge or tamper with claims like
  "sub" (user id) without invalidating the signature.
- Access tokens are short-lived on purpose: if one leaks, the blast
  radius is bounded by ACCESS_TOKEN_EXPIRE_MINUTES. We are not
  implementing refresh tokens yet (see README/TODO) — that's a
  deliberate scope cut, not an oversight.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import jwt, JWTError
from passlib.context import CryptContext

from app.core.config import settings
from app.core.exceptions import AttackGraphException

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

# CryptContext supports algorithm migration later (e.g. bcrypt -> argon2)
# without changing every call site — you just add the new scheme here.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password for storage. Never store plain_password itself."""
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check a plaintext password against a stored bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours


class AuthError(AttackGraphException):
    """Authentication failed (bad credentials, expired/invalid token)."""
    def __init__(self, message: str):
        super().__init__(message, code="AUTH_ERROR")


def create_access_token(subject: str, extra_claims: dict[str, Any] | None = None) -> str:
    """
    Create a signed JWT for the given subject (the account's id).

    `subject` becomes the "sub" claim — the standard JWT field for
    "who is this token about". We keep the payload minimal: just
    identity + expiry. Anything else (roles, plan, etc.) can be looked
    up server-side from the id instead of trusted from the token.
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": expire,
    }
    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and verify a JWT. Raises AuthError on any failure:
    bad signature, expired token, malformed token, etc.

    We intentionally collapse all jose failure modes into one AuthError
    rather than exposing which specific check failed — that avoids
    giving an attacker a signal about *why* a token was rejected.
    """
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as e:
        logger.warning(f"JWT verification failed: {e}")
        raise AuthError("Could not validate credentials")

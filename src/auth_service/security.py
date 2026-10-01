import hashlib
from datetime import timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from auth_service.config import Settings
from auth_service.models import now

hasher = PasswordHasher()
DUMMY_HASH = hasher.hash("a dummy password used for timing equalization")


def verify_password(encoded: str | None, password: str) -> bool:
    try:
        result = hasher.verify(encoded or DUMMY_HASH, password)
        return bool(encoded) and bool(result)
    except (VerificationError, InvalidHashError):
        return False


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def encode_token(
    settings: Settings, user_id: str, sid: str, jti: str, kind: str, seconds: int
) -> str:
    issued = now()
    return jwt.encode(
        {
            "sub": user_id,
            "sid": sid,
            "jti": jti,
            "type": kind,
            "iss": "auth-service-lab",
            "aud": kind,
            "iat": issued,
            "exp": issued + timedelta(seconds=seconds),
        },
        settings.jwt_secret,
        algorithm="HS256",
    )


def decode_token(settings: Settings, token: str, kind: str) -> dict[str, Any]:
    claims = jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=["HS256"],
        issuer="auth-service-lab",
        audience=kind,
        options={"require": ["sub", "sid", "jti", "type", "iat", "exp"]},
    )
    if claims["type"] != kind or any(
        not isinstance(claims[key], str) for key in ("sub", "sid", "jti")
    ):
        raise jwt.InvalidTokenError("Invalid token claims")
    return claims

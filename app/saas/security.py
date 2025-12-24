from __future__ import annotations
import os
from datetime import datetime, timedelta
from typing import Any, Optional

from jose import jwt
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET")
    if not secret:
        # Fail loudly in production
        raise RuntimeError("JWT_SECRET env var is required")
    return secret

def create_access_token(subject: str, expires_minutes: int = 60*24*7) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    return jwt.encode(payload, jwt_secret(), algorithm="HS256")

def decode_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, jwt_secret(), algorithms=["HS256"])

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass


@dataclass(slots=True)
class CodeEntry:
    api_key: str
    code_challenge: str
    code_challenge_method: str
    redirect_uri: str
    expires_at: float


_code_store: dict[str, CodeEntry] = {}
_refresh_store: dict[str, str] = {}

_AUTHORIZATION_CODE_TTL_SECONDS = 60
_ACCESS_TOKEN_TTL_SECONDS = 3600
_SUPPORTED_CODE_CHALLENGE_METHOD = "S256"


def _jwt_module():
    import jwt

    return jwt


def _base64url_sha256(value: str) -> str:
    digest = hashlib.sha256(value.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def generate_code(
    api_key: str,
    code_challenge: str,
    code_challenge_method: str,
    redirect_uri: str,
) -> str:
    if code_challenge_method != _SUPPORTED_CODE_CHALLENGE_METHOD:
        raise ValueError("only S256 PKCE code challenge method is supported")

    code = secrets.token_urlsafe(32)
    _code_store[code] = CodeEntry(
        api_key=api_key,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        redirect_uri=redirect_uri,
        expires_at=time.time() + _AUTHORIZATION_CODE_TTL_SECONDS,
    )
    return code


def consume_code(code: str, code_verifier: str) -> str | None:
    entry = _code_store.pop(code, None)
    if entry is None:
        return None

    if entry.expires_at < time.time():
        return None

    if entry.code_challenge_method != _SUPPORTED_CODE_CHALLENGE_METHOD:
        return None

    expected_challenge = _base64url_sha256(code_verifier)
    if not hmac.compare_digest(expected_challenge, entry.code_challenge):
        return None

    return entry.api_key


def issue_access_token(api_key: str, jwt_secret: str) -> tuple[str, str]:
    jwt = _jwt_module()
    now = int(time.time())
    access_token = jwt.encode(
        {
            "sub": api_key,
            "iat": now,
            "exp": now + _ACCESS_TOKEN_TTL_SECONDS,
            "type": "access",
        },
        jwt_secret,
        algorithm="HS256",
    )
    refresh_token = secrets.token_urlsafe(32)
    _refresh_store[refresh_token] = api_key
    return access_token, refresh_token


def verify_access_token(token: str, jwt_secret: str) -> str | None:
    jwt = _jwt_module()
    try:
        claims = jwt.decode(token, jwt_secret, algorithms=["HS256"])
    except Exception:
        return None

    if claims.get("type") != "access":
        return None

    api_key = claims.get("sub")
    if not isinstance(api_key, str) or not api_key:
        return None

    return api_key


def exchange_refresh_token(refresh_token: str, jwt_secret: str) -> tuple[str, str] | None:
    api_key = _refresh_store.pop(refresh_token, None)
    if api_key is None:
        return None

    return issue_access_token(api_key, jwt_secret)


__all__ = [
    "CodeEntry",
    "_code_store",
    "_refresh_store",
    "consume_code",
    "exchange_refresh_token",
    "generate_code",
    "issue_access_token",
    "verify_access_token",
]

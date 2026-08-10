from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass


@dataclass(slots=True)
class CodeEntry:
    api_key: str
    client_id: str
    code_challenge: str
    code_challenge_method: str
    redirect_uri: str
    expires_at: float


@dataclass(slots=True)
class AccessEntry:
    api_key: str
    expires_at: float


@dataclass(slots=True)
class RefreshEntry:
    api_key: str
    expires_at: float


_code_store: dict[str, CodeEntry] = {}
_access_store: dict[str, AccessEntry] = {}
_refresh_store: dict[str, RefreshEntry] = {}

_AUTHORIZATION_CODE_TTL_SECONDS = 60
_ACCESS_TOKEN_TTL_SECONDS = 3600
_DEFAULT_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60
_SUPPORTED_CODE_CHALLENGE_METHOD = "S256"


def _jwt_module():
    import jwt

    return jwt


def _base64url_sha256(value: str) -> str:
    digest = hashlib.sha256(value.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def _positive_int(raw: str | None) -> int | None:
    try:
        value = int(raw or "")
    except ValueError:
        return None
    return value if value > 0 else None


def _refresh_token_ttl_seconds() -> int:
    return (
        _positive_int(os.getenv("CONNECTOR_REFRESH_TOKEN_TTL_SECONDS"))
        or _DEFAULT_REFRESH_TOKEN_TTL_SECONDS
    )


def _prune_expired_access_tokens(now: float | None = None) -> None:
    current_time = time.time() if now is None else now
    expired_access_tokens = [
        session_id
        for session_id, entry in _access_store.items()
        if entry.expires_at < current_time
    ]
    for session_id in expired_access_tokens:
        _access_store.pop(session_id, None)


def _prune_expired_refresh_tokens(now: float | None = None) -> None:
    current_time = time.time() if now is None else now
    expired = [
        token
        for token, entry in _refresh_store.items()
        if entry.expires_at < current_time
    ]
    for token in expired:
        _refresh_store.pop(token, None)


def generate_code(
    api_key: str,
    client_id: str,
    code_challenge: str,
    code_challenge_method: str,
    redirect_uri: str,
) -> str:
    if code_challenge_method != _SUPPORTED_CODE_CHALLENGE_METHOD:
        raise ValueError("only S256 PKCE code challenge method is supported")

    code = secrets.token_urlsafe(32)
    _code_store[code] = CodeEntry(
        api_key=api_key,
        client_id=client_id,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        redirect_uri=redirect_uri,
        expires_at=time.time() + _AUTHORIZATION_CODE_TTL_SECONDS,
    )
    return code


def consume_code(
    code: str,
    code_verifier: str,
    redirect_uri: str,
    client_id: str,
) -> str | None:
    entry = _code_store.get(code)
    if entry is None:
        return None

    if entry.expires_at < time.time():
        _code_store.pop(code, None)
        return None

    if redirect_uri != entry.redirect_uri or client_id != entry.client_id:
        return None

    if entry.code_challenge_method != _SUPPORTED_CODE_CHALLENGE_METHOD:
        _code_store.pop(code, None)
        return None

    expected_challenge = _base64url_sha256(code_verifier)
    if not hmac.compare_digest(expected_challenge, entry.code_challenge):
        _code_store.pop(code, None)
        return None

    _code_store.pop(code, None)
    return entry.api_key


def issue_access_token(api_key: str, jwt_secret: str) -> tuple[str, str]:
    jwt = _jwt_module()
    now = int(time.time())
    expires_at = now + _ACCESS_TOKEN_TTL_SECONDS
    _prune_expired_access_tokens(now)
    _prune_expired_refresh_tokens(now)
    session_id = secrets.token_urlsafe(32)
    _access_store[session_id] = AccessEntry(api_key=api_key, expires_at=expires_at)
    access_token = jwt.encode(
        {
            "sub": session_id,
            "iat": now,
            "exp": expires_at,
            "type": "access",
        },
        jwt_secret,
        algorithm="HS256",
    )
    refresh_token = secrets.token_urlsafe(32)
    _refresh_store[refresh_token] = RefreshEntry(
        api_key=api_key,
        expires_at=now + _refresh_token_ttl_seconds(),
    )
    return access_token, refresh_token


def verify_access_token(token: str, jwt_secret: str) -> str | None:
    jwt = _jwt_module()
    try:
        claims = jwt.decode(token, jwt_secret, algorithms=["HS256"])
    except Exception:
        return None

    if claims.get("type") != "access":
        return None

    session_id = claims.get("sub")
    if not isinstance(session_id, str) or not session_id:
        return None

    entry = _access_store.get(session_id)
    if entry is None:
        return None
    if entry.expires_at < time.time():
        _access_store.pop(session_id, None)
        return None

    return entry.api_key


def exchange_refresh_token(refresh_token: str, jwt_secret: str) -> tuple[str, str] | None:
    entry = _refresh_store.pop(refresh_token, None)
    if entry is None:
        return None

    if entry.expires_at < time.time():
        return None

    return issue_access_token(entry.api_key, jwt_secret)


__all__ = [
    "AccessEntry",
    "CodeEntry",
    "RefreshEntry",
    "_access_store",
    "_code_store",
    "_refresh_store",
    "consume_code",
    "exchange_refresh_token",
    "generate_code",
    "issue_access_token",
    "verify_access_token",
]

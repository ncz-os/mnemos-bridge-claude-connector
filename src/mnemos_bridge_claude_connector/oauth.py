from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path


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


def _store_path() -> Path:
    configured = os.getenv("CONNECTOR_TOKEN_STORE_PATH", "").strip()
    if configured:
        return Path(configured).expanduser()
    state_home = os.getenv("XDG_STATE_HOME", "").strip()
    base = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    return base / "mnemos-bridge-claude-connector" / "oauth.sqlite3"


def _connect() -> sqlite3.Connection:
    path = _store_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    file_descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(file_descriptor)
    path.chmod(0o600)
    connection = sqlite3.connect(path, timeout=10.0)
    connection.execute("PRAGMA busy_timeout = 10000")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS connector_oauth_entries (
            kind TEXT NOT NULL,
            token TEXT NOT NULL,
            api_key TEXT NOT NULL,
            client_id TEXT,
            code_challenge TEXT,
            code_challenge_method TEXT,
            redirect_uri TEXT,
            expires_at REAL NOT NULL,
            PRIMARY KEY (kind, token)
        )
        """
    )
    return connection


def _save_entry(
    kind: str,
    token: str,
    api_key: str,
    expires_at: float,
    *,
    client_id: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    redirect_uri: str | None = None,
) -> None:
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO connector_oauth_entries (
                kind, token, api_key, client_id, code_challenge,
                code_challenge_method, redirect_uri, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                kind,
                token,
                api_key,
                client_id,
                code_challenge,
                code_challenge_method,
                redirect_uri,
                expires_at,
            ),
        )


def _prune_expired(kind: str, now: float | None = None) -> None:
    current_time = time.time() if now is None else now
    with _connect() as connection:
        connection.execute(
            "DELETE FROM connector_oauth_entries WHERE kind = ? AND expires_at < ?",
            (kind, current_time),
        )


def _clear_store() -> None:
    """Clear all OAuth entries. Intended for isolated tests and operator maintenance."""
    with _connect() as connection:
        connection.execute("DELETE FROM connector_oauth_entries")


def _entry_exists_for_test(kind: str, token: str) -> bool:
    with _connect() as connection:
        row = connection.execute(
            "SELECT 1 FROM connector_oauth_entries WHERE kind = ? AND token = ?",
            (kind, token),
        ).fetchone()
    return row is not None


def _entry_count_for_test(kind: str) -> int:
    with _connect() as connection:
        row = connection.execute(
            "SELECT COUNT(*) FROM connector_oauth_entries WHERE kind = ?",
            (kind,),
        ).fetchone()
    return int(row[0])


def _set_expiry_for_test(kind: str, token: str, expires_at: float) -> None:
    with _connect() as connection:
        connection.execute(
            "UPDATE connector_oauth_entries SET expires_at = ? WHERE kind = ? AND token = ?",
            (expires_at, kind, token),
        )


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
    _save_entry(
        "code",
        code,
        api_key,
        time.time() + _AUTHORIZATION_CODE_TTL_SECONDS,
        client_id=client_id,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        redirect_uri=redirect_uri,
    )
    return code


def consume_code(
    code: str,
    code_verifier: str,
    redirect_uri: str,
    client_id: str,
) -> str | None:
    with _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            """
            SELECT api_key, client_id, code_challenge, code_challenge_method,
                   redirect_uri, expires_at
            FROM connector_oauth_entries WHERE kind = 'code' AND token = ?
            """,
            (code,),
        ).fetchone()
        if row is None:
            return None

        entry = CodeEntry(*row)
        if entry.expires_at < time.time():
            connection.execute(
                "DELETE FROM connector_oauth_entries WHERE kind = 'code' AND token = ?",
                (code,),
            )
            return None

        if redirect_uri != entry.redirect_uri or client_id != entry.client_id:
            return None

        if entry.code_challenge_method != _SUPPORTED_CODE_CHALLENGE_METHOD:
            connection.execute(
                "DELETE FROM connector_oauth_entries WHERE kind = 'code' AND token = ?",
                (code,),
            )
            return None

        expected_challenge = _base64url_sha256(code_verifier)
        if not hmac.compare_digest(expected_challenge, entry.code_challenge):
            connection.execute(
                "DELETE FROM connector_oauth_entries WHERE kind = 'code' AND token = ?",
                (code,),
            )
            return None

        connection.execute(
            "DELETE FROM connector_oauth_entries WHERE kind = 'code' AND token = ?",
            (code,),
        )
        return entry.api_key


def issue_access_token(api_key: str, jwt_secret: str) -> tuple[str, str]:
    jwt = _jwt_module()
    now = int(time.time())
    expires_at = now + _ACCESS_TOKEN_TTL_SECONDS
    _prune_expired("access", now)
    _prune_expired("refresh", now)
    session_id = secrets.token_urlsafe(32)
    _save_entry("access", session_id, api_key, expires_at)
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
    _save_entry(
        "refresh",
        refresh_token,
        api_key,
        now + _refresh_token_ttl_seconds(),
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

    with _connect() as connection:
        row = connection.execute(
            """
            SELECT api_key, expires_at FROM connector_oauth_entries
            WHERE kind = 'access' AND token = ?
            """,
            (session_id,),
        ).fetchone()
        if row is None:
            return None
        entry = AccessEntry(*row)
        if entry.expires_at < time.time():
            connection.execute(
                "DELETE FROM connector_oauth_entries WHERE kind = 'access' AND token = ?",
                (session_id,),
            )
            return None
        return entry.api_key


def exchange_refresh_token(refresh_token: str, jwt_secret: str) -> tuple[str, str] | None:
    with _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            """
            SELECT api_key, expires_at FROM connector_oauth_entries
            WHERE kind = 'refresh' AND token = ?
            """,
            (refresh_token,),
        ).fetchone()
        if row is None:
            return None
        connection.execute(
            "DELETE FROM connector_oauth_entries WHERE kind = 'refresh' AND token = ?",
            (refresh_token,),
        )
        entry = RefreshEntry(*row)

    if entry.expires_at < time.time():
        return None

    return issue_access_token(entry.api_key, jwt_secret)


__all__ = [
    "AccessEntry",
    "CodeEntry",
    "RefreshEntry",
    "consume_code",
    "exchange_refresh_token",
    "generate_code",
    "issue_access_token",
    "verify_access_token",
]

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
_MAX_OUTSTANDING_CODES_PER_PRINCIPAL_CLIENT = 5
_MAX_CODE_ISSUANCES_PER_PRINCIPAL_CLIENT = 10
_CODE_ISSUANCE_WINDOW_SECONDS = 60

# API keys at rest are encrypted with AES-256-GCM. The data-encryption key is
# derived via HKDF-SHA256 from CONNECTOR_JWT_SECRET, so no new secret needs
# provisioning. Stored values carry a version prefix; rows written before
# encryption are kept readable and migrated to ciphertext on first read.
_API_KEY_CIPHERTEXT_PREFIX = "v1:"
_API_KEY_HKDF_SALT = b"mnemos-connector/api-key-at-rest/v1"
_API_KEY_HKDF_INFO = b"mnemos-connector oauth token store"
_AESGCM_NONCE_BYTES = 12
# Mirror the server's CONNECTOR_JWT_SECRET floor: HKDF adds no entropy, so a
# short secret would yield a weak data-encryption key.
_MIN_JWT_SECRET_LENGTH = 32


class AuthorizationCodeLimitExceeded(RuntimeError):
    pass


class ApiKeyDecryptionError(RuntimeError):
    """A stored MNEMOS API key could not be decrypted.

    Raised when the data-encryption key derived from the configured
    CONNECTOR_JWT_SECRET does not open a stored ciphertext row. This fails
    closed: callers must deny the request, not fall back to any other
    credential. The usual cause is a CONNECTOR_JWT_SECRET rotation, after
    which users must re-authorize (see README "Security Considerations").
    """


def _key_encryption_key(secret: str | None = None) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    raw = secret if secret is not None else os.getenv("CONNECTOR_JWT_SECRET", "")
    if not raw:
        raise RuntimeError("CONNECTOR_JWT_SECRET is required to encrypt stored API keys")
    # No CONNECTOR_ALLOW_WEAK_JWT_SECRET bypass here by design: HKDF adds no
    # entropy, so a weak secret would yield a weak data-encryption key while
    # the server still boots. Issuance fails closed instead.
    if len(raw) < _MIN_JWT_SECRET_LENGTH:
        raise RuntimeError(
            "CONNECTOR_JWT_SECRET must be at least 32 characters to encrypt stored API keys"
        )
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_API_KEY_HKDF_SALT,
        info=_API_KEY_HKDF_INFO,
    ).derive(raw.encode())


def _encrypt_api_key(api_key: str, secret: str | None = None) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(_AESGCM_NONCE_BYTES)
    ciphertext = AESGCM(_key_encryption_key(secret)).encrypt(nonce, api_key.encode(), None)
    return _API_KEY_CIPHERTEXT_PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode()


def _decrypt_api_key(stored: str, secret: str | None = None) -> str:
    """Decrypt a stored api_key value. Legacy plaintext rows pass through."""
    if not stored.startswith(_API_KEY_CIPHERTEXT_PREFIX):
        return stored
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        raw = base64.urlsafe_b64decode(stored[len(_API_KEY_CIPHERTEXT_PREFIX):].encode())
        nonce, ciphertext = raw[:_AESGCM_NONCE_BYTES], raw[_AESGCM_NONCE_BYTES:]
        return AESGCM(_key_encryption_key(secret)).decrypt(nonce, ciphertext, None).decode()
    except Exception as exc:
        raise ApiKeyDecryptionError(
            "stored MNEMOS API key cannot be decrypted with the configured "
            "CONNECTOR_JWT_SECRET (secret rotated or entry corrupted); "
            "the request is denied and the user must re-authorize"
        ) from exc


def _decode_and_migrate_api_key(
    connection: sqlite3.Connection,
    kind: str,
    token: str,
    stored: str,
    secret: str | None = None,
) -> str:
    """Return the plaintext API key for a row, migrating legacy rows in place."""
    if not stored.startswith(_API_KEY_CIPHERTEXT_PREFIX):
        connection.execute(
            "UPDATE connector_oauth_entries SET api_key = ? WHERE kind = ? AND token = ?",
            (_encrypt_api_key(stored, secret), kind, token),
        )
        return stored
    return _decrypt_api_key(stored, secret)


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
    stored = _encrypt_api_key(api_key)
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
                stored,
                client_id,
                code_challenge,
                code_challenge_method,
                redirect_uri,
                expires_at,
            ),
        )


def _count_entries_for_test_principal(
    connection: sqlite3.Connection, kind: str, api_key: str, client_id: str
) -> int:
    """Count live rows for a (kind, api_key, client_id) triple.

    api_key values are stored as randomized AES-GCM ciphertext, so the match
    must be evaluated in Python after decryption. Rows that no longer decrypt
    (e.g. after a CONNECTOR_JWT_SECRET rotation) count conservatively toward
    the limit so the rate limiter fails closed instead of resetting to zero.
    """
    count = 0
    rows = connection.execute(
        "SELECT api_key FROM connector_oauth_entries WHERE kind = ? AND client_id = ?",
        (kind, client_id),
    ).fetchall()
    for (stored,) in rows:
        try:
            plaintext = _decrypt_api_key(stored)
        except ApiKeyDecryptionError:
            count += 1
            continue
        if hmac.compare_digest(plaintext, api_key):
            count += 1
    return count


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
    now = time.time()
    with _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DELETE FROM connector_oauth_entries "
            "WHERE kind IN ('code', 'code_issue') AND expires_at <= ?",
            (now,),
        )
        outstanding = _count_entries_for_test_principal(connection, "code", api_key, client_id)
        recent_issuances = _count_entries_for_test_principal(
            connection, "code_issue", api_key, client_id
        )
        if (
            outstanding >= _MAX_OUTSTANDING_CODES_PER_PRINCIPAL_CLIENT
            or recent_issuances >= _MAX_CODE_ISSUANCES_PER_PRINCIPAL_CLIENT
        ):
            raise AuthorizationCodeLimitExceeded(
                "authorization code issuance limit exceeded"
            )
        connection.execute(
            """
            INSERT INTO connector_oauth_entries (
                kind, token, api_key, client_id, code_challenge,
                code_challenge_method, redirect_uri, expires_at
            ) VALUES ('code', ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                code,
                _encrypt_api_key(api_key),
                client_id,
                code_challenge,
                code_challenge_method,
                redirect_uri,
                now + _AUTHORIZATION_CODE_TTL_SECONDS,
            ),
        )
        connection.execute(
            """
            INSERT INTO connector_oauth_entries (
                kind, token, api_key, client_id, expires_at
            ) VALUES ('code_issue', ?, ?, ?, ?)
            """,
            (
                secrets.token_urlsafe(32),
                _encrypt_api_key(api_key),
                client_id,
                now + _CODE_ISSUANCE_WINDOW_SECONDS,
            ),
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
        # Code rows are single-use and deleted here, so decrypt without migrating.
        # An undecryptable row (e.g. after a CONNECTOR_JWT_SECRET rotation) fails
        # closed via ApiKeyDecryptionError; the DELETE above already removed it.
        return _decrypt_api_key(entry.api_key)


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
        try:
            return _decode_and_migrate_api_key(connection, "access", session_id, entry.api_key)
        except ApiKeyDecryptionError:
            return None


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
        entry = RefreshEntry(*row)

        if entry.expires_at < time.time():
            connection.execute(
                "DELETE FROM connector_oauth_entries WHERE kind = 'refresh' AND token = ?",
                (refresh_token,),
            )
            return None

        try:
            api_key = _decrypt_api_key(entry.api_key)
        except ApiKeyDecryptionError:
            connection.execute(
                "DELETE FROM connector_oauth_entries WHERE kind = 'refresh' AND token = ?",
                (refresh_token,),
            )
            return None
        # Rotation consumes the refresh token, so no migration write is needed.
        connection.execute(
            "DELETE FROM connector_oauth_entries WHERE kind = 'refresh' AND token = ?",
            (refresh_token,),
        )

    return issue_access_token(api_key, jwt_secret)


def peek_refresh_token(refresh_token: str) -> str | None:
    """Return the bound principal without consuming a valid refresh token."""
    with _connect() as connection:
        row = connection.execute(
            "SELECT api_key, expires_at FROM connector_oauth_entries "
            "WHERE kind = 'refresh' AND token = ?",
            (refresh_token,),
        ).fetchone()
        if row is None:
            return None
        entry = RefreshEntry(*row)
        if entry.expires_at < time.time():
            return None
        try:
            return _decode_and_migrate_api_key(
                connection, "refresh", refresh_token, entry.api_key
            )
        except ApiKeyDecryptionError:
            return None


__all__ = [
    "AccessEntry",
    "ApiKeyDecryptionError",
    "AuthorizationCodeLimitExceeded",
    "CodeEntry",
    "RefreshEntry",
    "consume_code",
    "exchange_refresh_token",
    "generate_code",
    "issue_access_token",
    "peek_refresh_token",
    "verify_access_token",
]

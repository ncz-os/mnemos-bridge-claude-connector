"""Regression tests for encrypted MNEMOS API keys at rest (NG3-DEC-12)."""

from __future__ import annotations

import base64
import os
import secrets
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

import pytest

os.environ["CONNECTOR_JWT_SECRET"] = "offline-test-secret-with-enough-entropy"
os.environ["CONNECTOR_TOKEN_STORE_PATH"] = os.path.join(
    tempfile.gettempdir(), f"mnemos-connector-at-rest-{os.getpid()}.sqlite3"
)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mnemos_bridge_claude_connector import oauth

JWT_SECRET_A = "secret-a-with-enough-entropy-for-hs256"
JWT_SECRET_B = "secret-b-with-enough-entropy-for-hs256"
API_KEY = "mnemos-api-key-abcdef-123456"


def setup_function() -> None:
    os.environ["CONNECTOR_JWT_SECRET"] = JWT_SECRET_A
    oauth._clear_store()


def _raw_api_key_values() -> list[str]:
    with sqlite3.connect(oauth._store_path()) as connection:
        return [row[0] for row in connection.execute("SELECT api_key FROM connector_oauth_entries")]


def _insert_legacy_plaintext(kind: str, token: str) -> None:
    with sqlite3.connect(oauth._store_path()) as connection:
        connection.execute(
            "INSERT INTO connector_oauth_entries (kind, token, api_key, expires_at)"
            " VALUES (?, ?, ?, ?)",
            (kind, token, API_KEY, time.time() + 3600),
        )


def _store_bytes() -> bytes:
    with open(oauth._store_path(), "rb") as handle:
        return handle.read()


def test_stored_rows_contain_no_plaintext_key_bytes() -> None:
    oauth.generate_code(
        API_KEY, "client-id", oauth._base64url_sha256("verifier"), "S256", "https://x.test/cb"
    )
    oauth.issue_access_token(API_KEY, JWT_SECRET_A)

    raw_values = _raw_api_key_values()
    assert raw_values, "expected rows in the token store"
    for stored in raw_values:
        assert stored.startswith("v1:"), "stored value must carry the versioned prefix"
        assert API_KEY not in stored
    assert API_KEY.encode() not in _store_bytes()


def test_access_and_refresh_round_trip_with_encrypted_store() -> None:
    verifier = "round-trip-verifier"
    code = oauth.generate_code(
        API_KEY, "client-id", oauth._base64url_sha256(verifier), "S256", "https://x.test/cb"
    )
    assert oauth.consume_code(code, verifier, "https://x.test/cb", "client-id") == API_KEY

    access_token, refresh_token = oauth.issue_access_token(API_KEY, JWT_SECRET_A)
    assert oauth.verify_access_token(access_token, JWT_SECRET_A) == API_KEY
    assert oauth.peek_refresh_token(refresh_token) == API_KEY
    exchanged = oauth.exchange_refresh_token(refresh_token, JWT_SECRET_A)
    assert exchanged is not None
    assert oauth.verify_access_token(exchanged[0], JWT_SECRET_A) == API_KEY


def test_legacy_plaintext_rows_are_migrated_on_first_read() -> None:
    legacy_refresh = "legacy-" + secrets.token_urlsafe(8)
    _insert_legacy_plaintext("refresh", legacy_refresh)
    assert API_KEY.encode() in _store_bytes()

    assert oauth.peek_refresh_token(legacy_refresh) == API_KEY

    with sqlite3.connect(oauth._store_path()) as connection:
        migrated = connection.execute(
            "SELECT api_key FROM connector_oauth_entries WHERE kind = 'refresh' AND token = ?",
            (legacy_refresh,),
        ).fetchone()[0]
    assert migrated.startswith("v1:")
    assert API_KEY not in migrated
    assert API_KEY.encode() not in _store_bytes()
    assert oauth.peek_refresh_token(legacy_refresh) == API_KEY


def test_wrong_secret_fails_closed_with_clear_error() -> None:
    _access_token, refresh_token = oauth.issue_access_token(API_KEY, JWT_SECRET_A)
    access_token = _access_token

    os.environ["CONNECTOR_JWT_SECRET"] = JWT_SECRET_B
    try:
        with pytest.raises(oauth.ApiKeyDecryptionError, match="CONNECTOR_JWT_SECRET"):
            oauth._decrypt_api_key(_raw_api_key_values()[0])
        # OAuth entry points deny the request instead of leaking or crashing.
        assert oauth.verify_access_token(access_token, JWT_SECRET_A) is None
        assert oauth.peek_refresh_token(refresh_token) is None
        assert oauth.exchange_refresh_token(refresh_token, JWT_SECRET_A) is None
    finally:
        os.environ["CONNECTOR_JWT_SECRET"] = JWT_SECRET_A


def test_ciphertext_uses_random_nonce() -> None:
    first = oauth._encrypt_api_key(API_KEY)
    second = oauth._encrypt_api_key(API_KEY)
    assert first != second
    assert oauth._decrypt_api_key(first) == API_KEY
    assert oauth._decrypt_api_key(second) == API_KEY
    payload = base64.urlsafe_b64decode(first[len("v1:"):].encode())
    assert len(payload) > 12 + len(API_KEY.encode())


def test_tampered_ciphertext_fails_closed() -> None:
    stored = oauth._encrypt_api_key(API_KEY)
    raw = bytearray(base64.urlsafe_b64decode(stored[len("v1:"):].encode()))
    raw[-1] ^= 0x01
    tampered = "v1:" + base64.urlsafe_b64encode(bytes(raw)).decode()
    with pytest.raises(oauth.ApiKeyDecryptionError, match="CONNECTOR_JWT_SECRET"):
        oauth._decrypt_api_key(tampered)


def test_weak_secret_is_rejected_for_encryption() -> None:
    with pytest.raises(RuntimeError, match="at least 32 characters"):
        oauth._encrypt_api_key(API_KEY, secret="short")
    with pytest.raises(RuntimeError, match="required"):
        oauth._encrypt_api_key(API_KEY, secret="")
    with pytest.raises(oauth.ApiKeyDecryptionError, match="CONNECTOR_JWT_SECRET"):
        oauth._decrypt_api_key(oauth._encrypt_api_key(API_KEY), secret="x" * 31 + "y")


def test_poisoned_refresh_row_is_deleted_and_denied() -> None:
    _access, refresh_token = oauth.issue_access_token(API_KEY, JWT_SECRET_A)
    os.environ["CONNECTOR_JWT_SECRET"] = JWT_SECRET_B
    try:
        assert oauth.exchange_refresh_token(refresh_token, JWT_SECRET_A) is None
    finally:
        os.environ["CONNECTOR_JWT_SECRET"] = JWT_SECRET_A
    assert not oauth._entry_exists_for_test("refresh", refresh_token)


def test_legacy_refresh_row_is_consumed_by_exchange_without_plaintext_residue() -> None:
    legacy_refresh = "legacy-xchg-" + secrets.token_urlsafe(8)
    _insert_legacy_plaintext("refresh", legacy_refresh)
    exchanged = oauth.exchange_refresh_token(legacy_refresh, JWT_SECRET_A)
    assert exchanged is not None
    assert oauth.verify_access_token(exchanged[0], JWT_SECRET_A) == API_KEY
    assert not oauth._entry_exists_for_test("refresh", legacy_refresh)
    assert API_KEY.encode() not in _store_bytes()


def test_rate_limit_counts_encrypted_rows() -> None:
    challenge = oauth._base64url_sha256("verifier")
    for _ in range(oauth._MAX_OUTSTANDING_CODES_PER_PRINCIPAL_CLIENT):
        oauth.generate_code(API_KEY, "client-id", challenge, "S256", "https://x.test/cb")
    with pytest.raises(oauth.AuthorizationCodeLimitExceeded):
        oauth.generate_code(API_KEY, "client-id", challenge, "S256", "https://x.test/cb")


def test_undecryptable_rows_count_conservatively_toward_rate_limit() -> None:
    challenge = oauth._base64url_sha256("verifier")
    oauth.generate_code(API_KEY, "client-id", challenge, "S256", "https://x.test/cb")
    os.environ["CONNECTOR_JWT_SECRET"] = JWT_SECRET_B
    try:
        with pytest.raises(oauth.AuthorizationCodeLimitExceeded):
            for _ in range(oauth._MAX_OUTSTANDING_CODES_PER_PRINCIPAL_CLIENT):
                oauth.generate_code(
                    "another-key", "client-id", challenge, "S256", "https://x.test/cb"
                )
    finally:
        os.environ["CONNECTOR_JWT_SECRET"] = JWT_SECRET_A

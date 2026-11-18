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
    # The store runs in WAL mode, so freshly written content may still sit in
    # the -wal sidecar; checkpoint first so the main file reflects everything.
    with sqlite3.connect(oauth._store_path()) as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
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
        # OAuth entry points deny the request instead of leaking or crashing
        # when the configured data-encryption secret cannot open the row.
        assert oauth.verify_access_token(access_token, JWT_SECRET_B) is None
        assert oauth.peek_refresh_token(refresh_token, JWT_SECRET_B) is None
        assert oauth.exchange_refresh_token(refresh_token, JWT_SECRET_B) is None
    finally:
        os.environ["CONNECTOR_JWT_SECRET"] = JWT_SECRET_A
    # The failed exchange above consumed (deleted) the poisoned row.
    assert not oauth._entry_exists_for_test("refresh", refresh_token)


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
        assert oauth.exchange_refresh_token(refresh_token, JWT_SECRET_B) is None
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


def test_save_entry_uses_caller_provided_secret_not_environment() -> None:
    """Regression: _save_entry must propagate `secret` to _encrypt_api_key.

    Without propagation the issued rows are keyed to the ambient
    CONNECTOR_JWT_SECRET, breaking callers that pass an explicit key.
    """
    real_secret_value = os.environ.get("CONNECTOR_JWT_SECRET")
    os.environ.pop("CONNECTOR_JWT_SECRET", None)
    try:
        access_token, refresh_token = oauth.issue_access_token(API_KEY, JWT_SECRET_A)
    finally:
        if real_secret_value is not None:
            os.environ["CONNECTOR_JWT_SECRET"] = real_secret_value
    # Rows encrypted with the explicit secret decrypt with it and survive a
    # JWT round-trip verified against the same secret.
    assert oauth.verify_access_token(access_token, JWT_SECRET_A) == API_KEY
    assert oauth.peek_refresh_token(refresh_token, JWT_SECRET_A) == API_KEY
    assert API_KEY.encode() not in _store_bytes()


def test_generate_code_uses_caller_provided_secret_for_rate_limit() -> None:
    """generate_code must encrypt and count with the caller-provided secret."""
    challenge = oauth._base64url_sha256("verifier-secret-propagation")
    real_secret_value = os.environ.get("CONNECTOR_JWT_SECRET")
    os.environ.pop("CONNECTOR_JWT_SECRET", None)
    try:
        code = oauth.generate_code(
            API_KEY, "client-id", challenge, "S256", "https://x.test/cb",
            secret=JWT_SECRET_A,
        )
        assert oauth.consume_code(
            code, "verifier-secret-propagation", "https://x.test/cb", "client-id",
            secret=JWT_SECRET_A,
        ) == API_KEY
    finally:
        if real_secret_value is not None:
            os.environ["CONNECTOR_JWT_SECRET"] = real_secret_value


def test_migration_encrypts_legacy_plaintext_exactly_once() -> None:
    """A legacy row must read back as the original key after migration.

    The legacy branch of _decode_and_migrate_api_key receives the raw
    plaintext in `stored`; encrypting the already-prefixed ciphertext a
    second time would make the row undecryptable (double encryption).
    """
    legacy_refresh = "legacy-once-" + secrets.token_urlsafe(8)
    _insert_legacy_plaintext("refresh", legacy_refresh)

    first = oauth.peek_refresh_token(legacy_refresh, JWT_SECRET_A)
    assert first == API_KEY

    migrated = oauth._raw_api_key_value_for_test("refresh", legacy_refresh)
    assert migrated.startswith("v1:")
    assert API_KEY not in migrated

    # Second read takes the decrypt path and returns the same plaintext.
    second = oauth.peek_refresh_token(legacy_refresh, JWT_SECRET_A)
    assert second == API_KEY


def test_consume_code_requires_the_storage_secret() -> None:
    """consume_code decrypts with the secret generate_code stored with.

    A wrong explicit secret fails closed (ApiKeyDecryptionError); the right
    one returns the principal. The PKCE verifier is never an encryption key.
    """
    import mnemos_bridge_claude_connector.oauth as oauth_module

    challenge = oauth_module._base64url_sha256("storage-secret-verifier")
    code = oauth.generate_code(
        API_KEY, "client-id", challenge, "S256", "https://x.test/cb",
        secret=JWT_SECRET_A,
    )
    with pytest.raises(oauth.ApiKeyDecryptionError, match="CONNECTOR_JWT_SECRET"):
        oauth.consume_code(
            code, "storage-secret-verifier", "https://x.test/cb", "client-id",
            secret=JWT_SECRET_B,
        )


def test_consume_code_without_secret_uses_environment() -> None:
    """consume_code(secret=None) falls back to CONNECTOR_JWT_SECRET (fail-closed)."""
    import mnemos_bridge_claude_connector.oauth as oauth_module

    challenge = oauth_module._base64url_sha256("env-fallback-verifier")
    code = oauth.generate_code(
        API_KEY, "client-id", challenge, "S256", "https://x.test/cb",
        secret=JWT_SECRET_A,
    )
    assert (
        oauth.consume_code(
            code, "env-fallback-verifier", "https://x.test/cb", "client-id",
        )
        == API_KEY
    )


def test_consume_code_rejects_non_string_secret_with_type_error() -> None:
    """A non-str secret is a programming error: TypeError, not a decrypt error."""
    challenge = oauth._base64url_sha256("type-check-verifier")
    code = oauth.generate_code(
        API_KEY, "client-id", challenge, "S256", "https://x.test/cb",
        secret=JWT_SECRET_A,
    )
    with pytest.raises(TypeError, match="secret must be a str or None"):
        oauth.consume_code(
            code, "type-check-verifier", "https://x.test/cb", "client-id",
            secret=12345,  # type: ignore[arg-type]
        )


def test_rate_limit_quota_recovers_after_secret_rotation_rows_expire() -> None:
    """A rotation can never permanently exhaust a principal's quota.

    Rows written under the old key fail closed and count toward the cap, but
    authorization codes and issuance markers live at most 60 seconds, so once
    they expire the principal can issue again under the new key.
    """
    challenge = oauth._base64url_sha256("quota-recovery-verifier")
    oauth.generate_code(
        API_KEY, "client-id", challenge, "S256", "https://x.test/cb",
        secret=JWT_SECRET_A,
    )
    os.environ["CONNECTOR_JWT_SECRET"] = JWT_SECRET_B
    try:
        # Old-key row is undecryptable under the new key: still fail closed.
        with pytest.raises(oauth.AuthorizationCodeLimitExceeded):
            for _ in range(oauth._MAX_OUTSTANDING_CODES_PER_PRINCIPAL_CLIENT):
                oauth.generate_code(
                    "another-key", "client-id", challenge, "S256", "https://x.test/cb",
                    secret=JWT_SECRET_B,
                )
        # Let every code/issuance row expire, then issuance works again.
        expired = __import__("time").time() - 1
        with oauth._connect() as connection:
            connection.execute(
                "UPDATE connector_oauth_entries SET expires_at = ? "
                "WHERE kind IN ('code', 'code_issue')",
                (expired,),
            )
        code = oauth.generate_code(
            "another-key", "client-id", challenge, "S256", "https://x.test/cb",
            secret=JWT_SECRET_B,
        )
        assert (
            oauth.consume_code(
                code, "quota-recovery-verifier", "https://x.test/cb", "client-id",
                secret=JWT_SECRET_B,
            )
            == "another-key"
        )
    finally:
        os.environ["CONNECTOR_JWT_SECRET"] = JWT_SECRET_A

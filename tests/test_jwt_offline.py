from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import jwt


os.environ["CONNECTOR_JWT_SECRET"] = "offline-test-secret-with-enough-entropy"
os.environ["CONNECTOR_TOKEN_STORE_PATH"] = os.path.join(
    tempfile.gettempdir(), f"mnemos-connector-jwt-{os.getpid()}.sqlite3"
)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mnemos_bridge_claude_connector import oauth  # noqa: E402


JWT_SECRET_A = "secret-a-with-enough-entropy-for-hs256"
JWT_SECRET_B = "secret-b-with-enough-entropy-for-hs256"


def setup_function() -> None:
    oauth._clear_store()


def test_access_token_round_trip() -> None:
    token, _refresh_token = oauth.issue_access_token("test-api-key", JWT_SECRET_A)

    assert oauth.verify_access_token(token, JWT_SECRET_A) == "test-api-key"


def test_oauth_entries_survive_a_fresh_process() -> None:
    verifier = "persistent-verifier"
    code = oauth.generate_code(
        "test-api-key",
        "client-id",
        oauth._base64url_sha256(verifier),
        "S256",
        "https://example.test/callback",
    )
    access_token, refresh_token = oauth.issue_access_token("test-api-key", JWT_SECRET_A)
    script = """
from mnemos_bridge_claude_connector import oauth
import sys
code, verifier, access_token, refresh_token, secret = sys.argv[1:]
print(oauth.consume_code(code, verifier, 'https://example.test/callback', 'client-id'))
print(oauth.verify_access_token(access_token, secret))
print(oauth.exchange_refresh_token(refresh_token, secret) is not None)
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")

    result = subprocess.run(
        [sys.executable, "-c", script, code, verifier, access_token, refresh_token, JWT_SECRET_A],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.stdout.splitlines() == ["test-api-key", "test-api-key", "True"]


def test_access_token_does_not_disclose_api_key_in_claims() -> None:
    token, _refresh_token = oauth.issue_access_token("test-api-key", JWT_SECRET_A)

    claims = jwt.decode(token, JWT_SECRET_A, algorithms=["HS256"])

    assert "test-api-key" not in claims.values()
    assert oauth._entry_exists_for_test("access", claims["sub"])


def test_access_token_wrong_secret_rejected() -> None:
    token, _refresh_token = oauth.issue_access_token("test-api-key", JWT_SECRET_A)

    assert oauth.verify_access_token(token, JWT_SECRET_B) is None


def test_expired_access_token_rejected() -> None:
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": "test-api-key",
            "iat": now - 7200,
            "exp": now - 3600,
            "type": "access",
        },
        JWT_SECRET_A,
        algorithm="HS256",
    )

    assert oauth.verify_access_token(token, JWT_SECRET_A) is None


def test_refresh_token_exchange_round_trip() -> None:
    _token, refresh_token = oauth.issue_access_token("test-api-key", JWT_SECRET_A)

    exchanged = oauth.exchange_refresh_token(refresh_token, JWT_SECRET_A)

    assert exchanged is not None
    new_access_token, new_refresh_token = exchanged
    assert oauth.verify_access_token(new_access_token, JWT_SECRET_A) == "test-api-key"
    assert new_refresh_token != refresh_token


def test_refresh_token_exchange_rejects_unknown_token() -> None:
    assert oauth.exchange_refresh_token("missing-refresh-token", JWT_SECRET_A) is None


def test_refresh_token_exchange_rejects_expired_token() -> None:
    _token, refresh_token = oauth.issue_access_token("test-api-key", JWT_SECRET_A)
    oauth._set_expiry_for_test("refresh", refresh_token, time.time() - 1)

    assert oauth.exchange_refresh_token(refresh_token, JWT_SECRET_A) is None

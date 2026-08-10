from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import jwt


os.environ["CONNECTOR_JWT_SECRET"] = "offline-test-secret-with-enough-entropy"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mnemos_bridge_claude_connector import oauth  # noqa: E402


JWT_SECRET_A = "secret-a-with-enough-entropy-for-hs256"
JWT_SECRET_B = "secret-b-with-enough-entropy-for-hs256"


def setup_function() -> None:
    oauth._code_store.clear()
    oauth._access_store.clear()
    oauth._refresh_store.clear()


def test_access_token_round_trip() -> None:
    token, _refresh_token = oauth.issue_access_token("test-api-key", JWT_SECRET_A)

    assert oauth.verify_access_token(token, JWT_SECRET_A) == "test-api-key"


def test_access_token_does_not_disclose_api_key_in_claims() -> None:
    token, _refresh_token = oauth.issue_access_token("test-api-key", JWT_SECRET_A)

    claims = jwt.decode(token, JWT_SECRET_A, algorithms=["HS256"])

    assert "test-api-key" not in claims.values()
    assert claims["sub"] in oauth._access_store


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
    oauth._refresh_store[refresh_token].expires_at = time.time() - 1

    assert oauth.exchange_refresh_token(refresh_token, JWT_SECRET_A) is None

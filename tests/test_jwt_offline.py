from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import jwt


os.environ.setdefault("CONNECTOR_JWT_SECRET", "offline-test-secret")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mnemos_bridge_claude_connector import oauth  # noqa: E402


def setup_function() -> None:
    oauth._code_store.clear()
    oauth._refresh_store.clear()


def test_access_token_round_trip() -> None:
    token, _refresh_token = oauth.issue_access_token("test-api-key", "secret-a")

    assert oauth.verify_access_token(token, "secret-a") == "test-api-key"


def test_access_token_wrong_secret_rejected() -> None:
    token, _refresh_token = oauth.issue_access_token("test-api-key", "secret-a")

    assert oauth.verify_access_token(token, "secret-b") is None


def test_expired_access_token_rejected() -> None:
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": "test-api-key",
            "iat": now - 7200,
            "exp": now - 3600,
            "type": "access",
        },
        "secret-a",
        algorithm="HS256",
    )

    assert oauth.verify_access_token(token, "secret-a") is None


def test_refresh_token_exchange_round_trip() -> None:
    _token, refresh_token = oauth.issue_access_token("test-api-key", "secret-a")

    exchanged = oauth.exchange_refresh_token(refresh_token, "secret-a")

    assert exchanged is not None
    new_access_token, new_refresh_token = exchanged
    assert oauth.verify_access_token(new_access_token, "secret-a") == "test-api-key"
    assert new_refresh_token != refresh_token


def test_refresh_token_exchange_rejects_unknown_token() -> None:
    assert oauth.exchange_refresh_token("missing-refresh-token", "secret-a") is None

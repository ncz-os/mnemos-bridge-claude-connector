from __future__ import annotations

import base64
import hashlib
import os
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest


os.environ.setdefault("CONNECTOR_JWT_SECRET", "offline-test-secret")
os.environ.setdefault("CONNECTOR_PUBLIC_URL", "http://connector.test")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mnemos_bridge_claude_connector import oauth  # noqa: E402
from mnemos_bridge_claude_connector import server as server_module  # noqa: E402


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


@pytest.fixture(autouse=True)
def _clear_oauth_stores() -> None:
    oauth._code_store.clear()
    oauth._refresh_store.clear()


@pytest.fixture
def authorize_params() -> dict[str, str]:
    return {
        "client_id": "claude-test-client",
        "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
        "state": "state-123",
        "code_challenge": _pkce_challenge("correct-verifier"),
        "code_challenge_method": "S256",
        "response_type": "code",
    }


@pytest.fixture
async def client(monkeypatch: pytest.MonkeyPatch) -> httpx.AsyncClient:
    async def fake_validate_mnemos_api_key(api_key: str) -> bool:
        return api_key == "valid-test-key"

    monkeypatch.setattr(server_module, "validate_mnemos_api_key", fake_validate_mnemos_api_key)
    transport = httpx.ASGITransport(app=server_module.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as test_client:
        yield test_client


async def _authorize_for_code(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
    *,
    api_key: str = "valid-test-key",
) -> str:
    response = await client.post(
        "/oauth/authorize",
        data={**authorize_params, "mnemos_api_key": api_key},
        follow_redirects=False,
    )
    assert response.status_code == 302
    location = response.headers["location"]
    query = parse_qs(urlsplit(location).query)
    return query["code"][0]


async def test_authorize_get_returns_html_form(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
) -> None:
    response = await client.get("/oauth/authorize", params=authorize_params)

    assert response.status_code == 200
    assert "<form" in response.text
    assert "MNEMOS API Key" in response.text
    assert "Authorize Claude" in response.text


async def test_authorize_post_valid_key_redirects_with_code_and_state(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
) -> None:
    response = await client.post(
        "/oauth/authorize",
        data={**authorize_params, "mnemos_api_key": "valid-test-key"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(authorize_params["redirect_uri"])
    query = parse_qs(urlsplit(location).query)
    assert query["code"][0]
    assert query["state"][0] == authorize_params["state"]


async def test_authorize_post_invalid_key_returns_html_error(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
) -> None:
    response = await client.post(
        "/oauth/authorize",
        data={**authorize_params, "mnemos_api_key": "bad-key"},
    )

    assert response.status_code == 200
    assert "Invalid API key. Please try again." in response.text


async def test_token_valid_code_and_pkce_verifier_returns_access_token(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
) -> None:
    code = await _authorize_for_code(client, authorize_params)

    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": "correct-verifier",
        },
    )

    payload = response.json()
    assert response.status_code == 200
    assert payload["access_token"]
    assert payload["token_type"] == "bearer"
    assert payload["expires_in"] == 3600
    assert payload["refresh_token"]


async def test_token_invalid_pkce_verifier_returns_oauth_error(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
) -> None:
    code = await _authorize_for_code(client, authorize_params)

    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": "wrong-verifier",
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


async def test_token_expired_code_returns_oauth_error(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
) -> None:
    code = await _authorize_for_code(client, authorize_params)
    oauth._code_store[code].expires_at = time.time() - 1

    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": "correct-verifier",
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


async def test_refresh_token_grant_returns_new_access_token(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
) -> None:
    code = await _authorize_for_code(client, authorize_params)
    token_response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": "correct-verifier",
        },
    )
    refresh_token = token_response.json()["refresh_token"]

    response = await client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
    )

    payload = response.json()
    assert response.status_code == 200
    assert payload["access_token"]
    assert payload["refresh_token"]
    assert payload["refresh_token"] != refresh_token


async def test_sse_without_bearer_returns_401(client: httpx.AsyncClient) -> None:
    response = await client.get("/sse")

    assert response.status_code == 401
    assert response.json()["error"] == "unauthorized"


async def test_sse_with_invalid_jwt_returns_401(client: httpx.AsyncClient) -> None:
    response = await client.get("/sse", headers={"Authorization": "Bearer not-a-jwt"})

    assert response.status_code == 401
    assert response.json()["error"] == "unauthorized"

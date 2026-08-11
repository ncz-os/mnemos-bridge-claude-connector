from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest


os.environ["CONNECTOR_JWT_SECRET"] = "offline-test-secret-with-enough-entropy"
os.environ.setdefault("CONNECTOR_PUBLIC_URL", "http://connector.test")
os.environ["CONNECTOR_TOKEN_STORE_PATH"] = os.path.join(
    tempfile.gettempdir(), f"mnemos-connector-oauth-flow-{os.getpid()}.sqlite3"
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mnemos_bridge_claude_connector import oauth  # noqa: E402
from mnemos_bridge_claude_connector import server as server_module  # noqa: E402


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        ({}, ["http://192.168.207.67:5002", "http://192.168.207.67:5003"]),
        ({"MNEMOS_BACKEND_URL": "http://combined.test"}, ["http://combined.test"] * 2),
        (
            {
                "MNEMOS_BACKEND_URL": "http://combined.test",
                "MNEMOS_API_URL": "http://api.test",
                "MNEMOS_MCP_URL": "http://mcp.test",
            },
            ["http://api.test", "http://mcp.test"],
        ),
    ],
)
def test_backend_url_configuration_combinations(
    settings: dict[str, str],
    expected: list[str],
) -> None:
    env = os.environ.copy()
    for name in ("MNEMOS_BACKEND_URL", "MNEMOS_API_URL", "MNEMOS_MCP_URL"):
        env.pop(name, None)
    env.update(settings)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from mnemos_bridge_claude_connector.server import MNEMOS_API_URL, MNEMOS_MCP_URL; "
                "print(MNEMOS_API_URL); print(MNEMOS_MCP_URL)"
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.stdout.splitlines() == expected


@pytest.fixture(autouse=True)
def _clear_oauth_stores() -> None:
    oauth._clear_store()


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
    monkeypatch.setenv("MNEMOS_MCP_TOKEN", "configured-mcp-token")
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


async def test_authorize_post_rejects_unallowed_redirect_uri(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
) -> None:
    response = await client.post(
        "/oauth/authorize",
        data={
            **authorize_params,
            "redirect_uri": "https://attacker.example/callback",
            "mnemos_api_key": "valid-test-key",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "Unsupported redirect_uri" in response.text
    assert oauth._entry_count_for_test("code") == 0


async def test_authorize_post_allows_configured_loopback_redirect(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONNECTOR_ALLOWED_REDIRECT_URIS", "http://localhost:8765/callback")

    response = await client.post(
        "/oauth/authorize",
        data={
            **authorize_params,
            "redirect_uri": "http://localhost:8765/callback",
            "mnemos_api_key": "valid-test-key",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302


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
            "client_id": authorize_params["client_id"],
            "redirect_uri": authorize_params["redirect_uri"],
        },
    )

    payload = response.json()
    assert response.status_code == 200
    assert payload["access_token"]
    assert payload["token_type"] == "bearer"
    assert payload["expires_in"] == 3600
    assert payload["refresh_token"]
    assert (
        oauth.verify_access_token(payload["access_token"], server_module.CONNECTOR_JWT_SECRET)
        == "configured-mcp-token"
    )


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
            "client_id": authorize_params["client_id"],
            "redirect_uri": authorize_params["redirect_uri"],
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


async def test_token_expired_code_returns_oauth_error(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
) -> None:
    code = await _authorize_for_code(client, authorize_params)
    oauth._set_expiry_for_test("code", code, time.time() - 1)

    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": "correct-verifier",
            "client_id": authorize_params["client_id"],
            "redirect_uri": authorize_params["redirect_uri"],
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
            "client_id": authorize_params["client_id"],
            "redirect_uri": authorize_params["redirect_uri"],
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


@pytest.mark.parametrize(
    ("field", "mismatched_value"),
    [
        ("client_id", "different-client"),
        ("redirect_uri", "https://wrong.example/callback"),
    ],
)
async def test_token_rejects_code_binding_mismatch_without_consuming_code(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
    field: str,
    mismatched_value: str,
) -> None:
    code = await _authorize_for_code(client, authorize_params)
    token_params = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": "correct-verifier",
        "client_id": authorize_params["client_id"],
        "redirect_uri": authorize_params["redirect_uri"],
        field: mismatched_value,
    }

    response = await client.post("/oauth/token", data=token_params)

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    assert oauth._entry_exists_for_test("code", code)


async def test_sse_without_bearer_returns_401(client: httpx.AsyncClient) -> None:
    response = await client.get("/sse")

    assert response.status_code == 401
    assert response.json()["error"] == "unauthorized"


async def test_sse_with_invalid_jwt_returns_401(client: httpx.AsyncClient) -> None:
    response = await client.get("/sse", headers={"Authorization": "Bearer not-a-jwt"})

    assert response.status_code == 401
    assert response.json()["error"] == "unauthorized"


async def test_validate_mnemos_api_key_requires_authenticated_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[tuple[str, dict[str, str]]] = []

    class _Response:
        status_code = 200

        def json(self) -> dict[str, object]:
            return {"authenticated": False, "user_id": "default"}

    class _Client:
        def __init__(self, *, timeout: float):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, url: str, headers: dict[str, str]):
            requests.append((url, headers))
            return _Response()

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    monkeypatch.setattr(server_module, "MNEMOS_API_URL", "http://mnemos-api.test")

    assert await server_module.validate_mnemos_api_key("candidate-key") is False
    assert requests == [
        (
            "http://mnemos-api.test/auth/oauth/me",
            {"Authorization": "Bearer candidate-key"},
        )
    ]


async def test_authorize_get_rejects_missing_client_id(client: httpx.AsyncClient) -> None:
    response = await client.get(
        "/oauth/authorize",
        params={
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "code_challenge": "challenge",
            "code_challenge_method": "S256",
            "response_type": "code",
        },
    )

    assert response.status_code == 400
    assert "Missing client_id" in response.text


async def test_authorize_post_rejects_missing_client_id_before_key_validation(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    async def fail_if_called(_api_key: str) -> bool:
        nonlocal called
        called = True
        return True

    monkeypatch.setattr(server_module, "validate_mnemos_api_key", fail_if_called)
    response = await client.post(
        "/oauth/authorize",
        data={**authorize_params, "client_id": "", "mnemos_api_key": "valid-test-key"},
    )

    assert response.status_code == 400
    assert "Missing client_id" in response.text
    assert called is False
    assert oauth._entry_count_for_test("code") == 0


async def test_authorize_returns_503_when_validation_backend_is_unavailable(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def unavailable(_api_key: str) -> bool:
        raise server_module.MnemosValidationUnavailable("connection failed")

    monkeypatch.setattr(server_module, "validate_mnemos_api_key", unavailable)
    response = await client.post(
        "/oauth/authorize",
        data={**authorize_params, "mnemos_api_key": "valid-test-key"},
    )

    assert response.status_code == 503
    assert "temporarily unavailable" in response.text
    assert "Invalid API key" not in response.text


async def test_validate_mnemos_api_key_raises_on_connection_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Client:
        def __init__(self, *, timeout: float):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, *_args: object, **_kwargs: object):
            raise httpx.ConnectError("offline")

    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    with pytest.raises(server_module.MnemosValidationUnavailable):
        await server_module.validate_mnemos_api_key("valid-test-key")


async def test_authorize_uses_provisioned_per_user_mcp_token(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MNEMOS_MCP_TOKEN", raising=False)
    monkeypatch.setenv(
        "MNEMOS_MCP_TOKENS",
        "other-user:other-mcp-token:other-api-key,test-user:user-mcp-token:valid-test-key",
    )

    code = await _authorize_for_code(client, authorize_params)

    assert (
        oauth.consume_code(
            code,
            "correct-verifier",
            authorize_params["redirect_uri"],
            authorize_params["client_id"],
        )
        == "user-mcp-token"
    )


async def test_authorize_supports_upstream_two_field_token_mapping(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MNEMOS_MCP_TOKEN", raising=False)
    monkeypatch.setenv("MNEMOS_MCP_TOKENS", "test-user:valid-test-key")

    code = await _authorize_for_code(client, authorize_params)

    assert (
        oauth.consume_code(
            code,
            "correct-verifier",
            authorize_params["redirect_uri"],
            authorize_params["client_id"],
        )
        == "valid-test-key"
    )


async def test_per_user_mapping_takes_precedence_over_shared_token(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MNEMOS_MCP_TOKEN", "ignored-shared-token")
    monkeypatch.setenv(
        "MNEMOS_MCP_TOKENS",
        "test-user:user-mcp-token:valid-test-key",
    )

    code = await _authorize_for_code(client, authorize_params)

    assert (
        oauth.consume_code(
            code,
            "correct-verifier",
            authorize_params["redirect_uri"],
            authorize_params["client_id"],
        )
        == "user-mcp-token"
    )


async def test_authorize_rejects_valid_but_unprovisioned_mcp_key(
    client: httpx.AsyncClient,
    authorize_params: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MNEMOS_MCP_TOKEN", raising=False)
    monkeypatch.delenv("MNEMOS_MCP_TOKENS", raising=False)

    response = await client.post(
        "/oauth/authorize",
        data={**authorize_params, "mnemos_api_key": "valid-test-key"},
    )

    assert response.status_code == 403
    assert "not provisioned for MCP access" in response.text
    assert oauth._entry_count_for_test("code") == 0


async def test_routes_proxy_to_mcp_url(
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[str] = []

    async def fake_sse_proxy(_request: object, backend_url: str, _secret: str):
        captured.append(backend_url)
        return server_module._oauth_error("test", "test", status_code=418)

    async def fake_messages_proxy(_request: object, backend_url: str, _secret: str):
        captured.append(backend_url)
        return server_module._oauth_error("test", "test", status_code=418)

    monkeypatch.setattr(server_module, "MNEMOS_MCP_URL", "http://mnemos-mcp.test")
    monkeypatch.setattr(server_module, "sse_proxy", fake_sse_proxy)
    monkeypatch.setattr(server_module, "messages_proxy", fake_messages_proxy)

    assert (await client.get("/sse")).status_code == 418
    assert (await client.post("/messages/")).status_code == 418
    assert captured == ["http://mnemos-mcp.test", "http://mnemos-mcp.test"]

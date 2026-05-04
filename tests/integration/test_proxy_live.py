from __future__ import annotations

import os
import sys
from pathlib import Path

import httpx
import pytest


pytestmark = pytest.mark.skipif(
    not os.getenv("MNEMOS_TEST_BASE"),
    reason="MNEMOS_TEST_BASE is not set",
)

os.environ.setdefault("CONNECTOR_JWT_SECRET", "integration-test-secret")
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from mnemos_bridge_claude_connector import oauth  # noqa: E402
from mnemos_bridge_claude_connector import server as server_module  # noqa: E402


async def test_live_messages_proxy_initialize(monkeypatch: pytest.MonkeyPatch) -> None:
    api_key = os.getenv("MNEMOS_TEST_API_KEY")
    if not api_key:
        pytest.skip("MNEMOS_TEST_API_KEY is not set")

    backend_url = os.environ["MNEMOS_TEST_BASE"].rstrip("/")
    monkeypatch.setattr(server_module, "MNEMOS_BACKEND_URL", backend_url)

    access_token, _refresh_token = oauth.issue_access_token(
        api_key,
        server_module.CONNECTOR_JWT_SECRET,
    )
    transport = httpx.ASGITransport(app=server_module.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/messages/",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            json={
                "jsonrpc": "2.0",
                "id": "integration-initialize",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "mnemos-bridge-claude-connector-tests",
                        "version": "0.1.0",
                    },
                },
            },
        )

    assert response.status_code < 500
    assert response.status_code not in {401, 403}
    assert response.content

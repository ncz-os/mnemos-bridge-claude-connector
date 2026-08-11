from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


os.environ["CONNECTOR_JWT_SECRET"] = "offline-test-secret-with-enough-entropy"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mnemos_bridge_claude_connector import proxy  # noqa: E402


class _HeaderRequest:
    headers = {
        "authorization": "Bearer connector-token",
        "host": "attacker.example",
        "content-length": "999",
        "connection": "keep-alive",
        "accept": "text/event-stream",
        "x-request-id": "req-1",
    }


class _StreamRequest:
    headers = {}

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def stream(self):
        for chunk in self._chunks:
            yield chunk


class _MessagesRequest(_StreamRequest):
    headers = {"authorization": "Bearer connector-token"}

    class _QueryParams:
        @staticmethod
        def multi_items() -> list[tuple[str, str]]:
            return [("session_id", "abc"), ("tag", "one"), ("tag", "two")]

    query_params = _QueryParams()


def test_headers_with_swapped_authorization_drops_hop_by_hop_headers() -> None:
    headers = proxy._headers_with_swapped_authorization(_HeaderRequest(), "mnemos-key")

    assert headers == {
        "accept": "text/event-stream",
        "x-request-id": "req-1",
        "Authorization": "Bearer mnemos-key",
    }


@pytest.mark.asyncio
async def test_read_body_limited_rejects_oversized_message(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONNECTOR_MAX_BODY_BYTES", "4")

    with pytest.raises(proxy._PayloadTooLarge):
        await proxy._read_body_limited(_StreamRequest([b"ab", b"cd", b"e"]))


@pytest.mark.asyncio
async def test_read_body_limited_allows_exact_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONNECTOR_MAX_BODY_BYTES", "4")

    assert await proxy._read_body_limited(_StreamRequest([b"ab", b"cd"])) == b"abcd"


@pytest.mark.asyncio
async def test_messages_proxy_forwards_all_query_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    posted: dict[str, object] = {}

    class _Upstream:
        content = b"accepted"
        status_code = 202
        headers: dict[str, str] = {}

    class _Client:
        def __init__(self, *, timeout: object):
            posted["timeout"] = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def post(self, url: str, **kwargs: object) -> _Upstream:
            posted["url"] = url
            posted.update(kwargs)
            return _Upstream()

    class _Httpx:
        AsyncClient = _Client
        HTTPError = Exception

        @staticmethod
        def Timeout(value: float) -> tuple[str, float]:
            return ("timeout", value)

    monkeypatch.setattr(proxy, "verify_access_token", lambda *_args: "mnemos-key")
    monkeypatch.setattr(proxy, "_httpx_module", lambda: _Httpx)

    response = await proxy.messages_proxy(
        _MessagesRequest([b"message"]),
        "http://mnemos.test",
        "jwt-secret",
    )

    assert response.status_code == 202
    assert posted["url"] == "http://mnemos.test/messages/"
    assert posted["params"] == [
        ("session_id", "abc"),
        ("tag", "one"),
        ("tag", "two"),
    ]
    assert posted["timeout"] == ("timeout", 30.0)


@pytest.mark.asyncio
async def test_messages_proxy_rejects_revoked_bound_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upstream_called = False

    async def revoked(api_key: str) -> str | None:
        assert api_key == "original-api-key"
        return None

    def fail_httpx():
        nonlocal upstream_called
        upstream_called = True
        raise AssertionError("revoked credentials must not reach MCP")

    monkeypatch.setattr(proxy, "verify_access_token", lambda *_args: "original-api-key")
    monkeypatch.setattr(proxy, "_httpx_module", fail_httpx)

    response = await proxy.messages_proxy(
        _MessagesRequest([b"message"]),
        "http://mnemos.test",
        "jwt-secret",
        revoked,
    )

    assert response.status_code == 401
    assert upstream_called is False

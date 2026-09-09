from __future__ import annotations

import json
import logging
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


@pytest.mark.asyncio
async def test_messages_proxy_redacts_backend_url_credentials_from_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend_url = "https://connector-user:userinfo-secret@mnemos.test/api?access_token=query-secret"

    class _Client:
        def __init__(self, *, timeout: object):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def post(self, url: str, **_kwargs: object) -> None:
            raise _Httpx.HTTPError(f"request failed for {url}")

    class _Httpx:
        AsyncClient = _Client
        HTTPError = RuntimeError

        @staticmethod
        def Timeout(value: float) -> tuple[str, float]:
            return ("timeout", value)

    monkeypatch.setattr(proxy, "verify_access_token", lambda *_args: "mnemos-key")
    monkeypatch.setattr(proxy, "_httpx_module", lambda: _Httpx)

    response = await proxy.messages_proxy(_MessagesRequest([b"message"]), backend_url, "jwt-secret")
    payload = json.loads(response.body)

    assert response.status_code == 502
    assert "userinfo-secret" not in payload["detail"]
    assert "query-secret" not in payload["detail"]
    assert "***REDACTED***" in payload["detail"]


@pytest.mark.asyncio
async def test_sse_proxy_redacts_backend_url_credentials_from_streaming_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend_url = "https://stream-user:userinfo-secret@mnemos.test?sig=query-secret"

    class _Upstream:
        status_code = 200

        async def aiter_bytes(self):
            if False:
                yield b""
            raise _Httpx.HTTPError(f"stream failed for {backend_url}")

    class _StreamContext:
        async def __aenter__(self) -> _Upstream:
            return _Upstream()

        async def __aexit__(self, *_args: object) -> None:
            return None

    class _Client:
        def __init__(self, *, timeout: object):
            pass

        def stream(self, *_args: object, **_kwargs: object) -> _StreamContext:
            return _StreamContext()

        async def aclose(self) -> None:
            return None

    class _Httpx:
        AsyncClient = _Client
        HTTPError = RuntimeError

    monkeypatch.setattr(proxy, "verify_access_token", lambda *_args: "mnemos-key")
    monkeypatch.setattr(proxy, "_httpx_module", lambda: _Httpx)
    monkeypatch.setattr(proxy, "_streaming_response", lambda body, status_code: body)

    body = await proxy.sse_proxy(_MessagesRequest([]), backend_url, "jwt-secret")
    with pytest.raises(RuntimeError) as exc_info:
        async for _chunk in body:
            pass

    detail = str(exc_info.value)
    assert "userinfo-secret" not in detail
    assert "query-secret" not in detail
    assert "***REDACTED***" in detail


def test_httpx_request_log_redacts_backend_url_credentials(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import httpx

    backend_url = (
        "https://logging-user:userinfo-secret@mnemos.test/messages"
        "?sig=query-secret#access_token=fragment-secret"
    )
    proxy.install_httpx_log_redaction()
    caplog.set_level(logging.INFO, logger="httpx")

    httpx_logger = logging.getLogger("httpx")
    httpx_logger.info(
        'HTTP Request: GET %s "HTTP/1.1 200 OK"', httpx.URL(backend_url)
    )
    httpx_logger.info(
        "HTTP Request: GET %s",
        httpx.URL("https://mnemos.test/path#access_token=fragment-only-secret"),
    )
    try:
        raise RuntimeError(f"request failed for {backend_url}")
    except RuntimeError:
        httpx_logger.exception("HTTP request raised")

    assert "userinfo-secret" not in caplog.text
    assert "query-secret" not in caplog.text
    assert "fragment-secret" not in caplog.text
    assert "fragment-only-secret" not in caplog.text
    assert "***REDACTED***" in caplog.text

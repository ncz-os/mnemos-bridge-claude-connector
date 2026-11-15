from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

os.environ["CONNECTOR_JWT_SECRET"] = "offline-test-secret-with-enough-entropy"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mnemos_bridge_claude_connector import proxy  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_sse_slots():
    proxy._active_sse_streams.clear()
    yield
    proxy._active_sse_streams.clear()


class _SwappedHeaderRequest:
    headers = {
        "authorization": "Bearer connector-token",
        "cookie": "session=abc",
        "Cookie": "session=abc",
        "x-forwarded-for": "1.2.3.4",
        "X-Forwarded-Host": "evil.example",
        "x-forwarded-proto": "https",
        "forwarded": "for=1.2.3.4",
        "Forwarded": "for=1.2.3.4",
        "accept": "text/event-stream",
        "x-request-id": "req-1",
    }


def test_swapped_headers_strip_cookie_and_forwarding_headers() -> None:
    headers = proxy._headers_with_swapped_authorization(_SwappedHeaderRequest(), "mnemos-key")

    lowered = {name.lower() for name in headers}
    assert "cookie" not in lowered
    assert "forwarded" not in lowered
    assert not any(name.startswith("x-forwarded-") for name in lowered)
    assert headers == {
        "accept": "text/event-stream",
        "x-request-id": "req-1",
        "Authorization": "Bearer mnemos-key",
    }


def _sse_harness(monkeypatch: pytest.MonkeyPatch, chunks: list[bytes]):
    seen: dict[str, object] = {}

    class _Upstream:
        status_code = 200

        async def aiter_bytes(self):
            for chunk in chunks:
                yield chunk

    class _StreamContext:
        async def __aenter__(self):
            return _Upstream()

        async def __aexit__(self, *_args: object):
            return None

    class _Client:
        def stream(self, *_args: object, **kwargs: object):
            seen["headers"] = kwargs.get("headers")
            return _StreamContext()

        async def aclose(self):
            return None

    class _Httpx:
        @staticmethod
        def AsyncClient(**kwargs):
            return _Client()

        HTTPError = RuntimeError

    monkeypatch.setattr(proxy, "verify_access_token", lambda *_args: "principal-1")
    monkeypatch.setattr(proxy, "_httpx_module", lambda: _Httpx)
    monkeypatch.setattr(proxy, "_streaming_response", lambda body, status_code: (body, status_code))
    return seen


class _AuthRequest:
    headers = {"authorization": "Bearer connector-token"}


@pytest.mark.asyncio
async def test_sse_fifth_concurrent_stream_returns_429(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONNECTOR_MAX_STREAMS_PER_PRINCIPAL", "4")
    _sse_harness(monkeypatch, [b"data: hi\n\n"])

    held: list[tuple] = []
    for _ in range(4):
        body, status = await proxy.sse_proxy(_AuthRequest(), "http://mnemos.test", "jwt")
        assert status == 200
        held.append((body, status))

    response = await proxy.sse_proxy(_AuthRequest(), "http://mnemos.test", "jwt")
    assert response.status_code == 429

    # Releasing one slot admits a new stream again.
    async for _ in held[0][0]:
        pass
    body, status = await proxy.sse_proxy(_AuthRequest(), "http://mnemos.test", "jwt")
    assert status == 200
    async for _ in body:
        pass
    for body_iter, _ in held[1:]:
        async for _ in body_iter:
            pass


@pytest.mark.asyncio
async def test_sse_idle_upstream_closed_after_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONNECTOR_SSE_IDLE_TIMEOUT_SECONDS", "0.05")

    class _HangingUpstream:
        status_code = 200

        async def aiter_bytes(self):
            await asyncio.sleep(10)
            yield b"never"

    class _StreamContext:
        async def __aenter__(self):
            return _HangingUpstream()

        async def __aexit__(self, *_args: object):
            return None

    class _Client:
        def stream(self, *args: object, **kwargs: object):
            return _StreamContext()

        async def aclose(self):
            return None

    class _Httpx:
        @staticmethod
        def AsyncClient(**kwargs):
            return _Client()

        HTTPError = RuntimeError

    monkeypatch.setattr(proxy, "verify_access_token", lambda *_args: "principal-idle")
    monkeypatch.setattr(proxy, "_httpx_module", lambda: _Httpx)
    monkeypatch.setattr(proxy, "_streaming_response", lambda body, status_code: (body, status_code))

    body, status = await proxy.sse_proxy(_AuthRequest(), "http://mnemos.test", "jwt")
    assert status == 200
    received = [chunk async for chunk in body]
    assert received == []
    # Slot released after the timed-out stream ends.
    assert proxy._active_sse_streams.get("principal-idle") in (None, 0)

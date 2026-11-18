from __future__ import annotations

import asyncio
import contextlib
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


@pytest.mark.asyncio
async def test_sse_handshake_failure_closes_client_and_releases_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONNECTOR_MAX_STREAMS_PER_PRINCIPAL", "4")

    telemetry: dict[str, bool] = {"client_closed": False}

    class _HandshakeError(Exception):
        pass

    state = {"entered": False}

    class _OkUpstream:
        status_code = 200

        async def aiter_bytes(self):
            yield b"data: ok\n\n"

    class _StreamContext:
        async def __aenter__(self):
            if not state["entered"]:
                state["entered"] = True
                raise _HandshakeError("handshake failed")
            return _OkUpstream()

        async def __aexit__(self, *_args: object):
            return None

    class _Client:
        def stream(self, *_args: object, **kwargs: object):
            return _StreamContext()

        async def aclose(self):
            telemetry["client_closed"] = True

    class _Httpx:
        @staticmethod
        def AsyncClient(**kwargs):
            return _Client()

        HTTPError = RuntimeError

    monkeypatch.setattr(proxy, "verify_access_token", lambda *_args: "principal-hs")
    monkeypatch.setattr(proxy, "_httpx_module", lambda: _Httpx)
    monkeypatch.setattr(
        proxy, "_streaming_response", lambda body, status_code: (body, status_code)
    )

    # A non-httpx failure during the handshake propagates out of sse_proxy
    # (it is not translated to a 502), but cleanup still runs.
    with pytest.raises(_HandshakeError, match="handshake failed"):
        await proxy.sse_proxy(_AuthRequest(), "http://mnemos.test", "jwt")

    # The client was closed and the slot was released even though the stream
    # was never entered.
    assert telemetry["client_closed"] is True
    assert proxy._active_sse_streams.get("principal-hs") in (None, 0)
    # The slot was released: a fresh stream is admitted.
    body, status = await proxy.sse_proxy(_AuthRequest(), "http://mnemos.test", "jwt")
    assert status == 200
    async for _ in body:
        pass


@pytest.mark.asyncio
async def test_sse_handshake_timeout_maps_to_502_and_releases_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONNECTOR_SSE_IDLE_TIMEOUT_SECONDS", "0.01")

    telemetry: dict[str, bool] = {"client_closed": False}

    class _StreamContext:
        async def __aenter__(self):
            # Hang past the idle timeout so the handshake window closes with a
            # TimeoutError; the stream is never entered (stream_owned stays
            # False), but the client and slot must still be released.
            await asyncio.sleep(10)

        async def __aexit__(self, *_args: object):
            return None

    class _Client:
        def stream(self, *_args: object, **kwargs: object):
            return _StreamContext()

        async def aclose(self):
            telemetry["client_closed"] = True

    class _Httpx:
        @staticmethod
        def AsyncClient(**kwargs):
            return _Client()

        HTTPError = RuntimeError

    monkeypatch.setattr(proxy, "verify_access_token", lambda *_args: "principal-timeout")
    monkeypatch.setattr(proxy, "_httpx_module", lambda: _Httpx)
    monkeypatch.setattr(proxy, "_streaming_response", lambda body, status_code: (body, status_code))

    # A TimeoutError from the bounded handshake is treated like an httpx error:
    # it returns a 502 bad_gateway rather than propagating as a 500.
    response = await proxy.sse_proxy(_AuthRequest(), "http://mnemos.test", "jwt")
    assert response.status_code == 502
    assert b"bad_gateway" in response.body
    # Resources were cleaned up despite the stream never being entered.
    assert telemetry["client_closed"] is True
    assert proxy._active_sse_streams.get("principal-timeout") in (None, 0)


@pytest.mark.asyncio
async def test_teardown_cancellation_safety_releases_all_resources() -> None:
    """If teardown() runs inside an already-cancelled task (the client-disconnect
    scenario), every resource -- the stream, the client, and the slot -- is still
    released because the body retries on CancelledError.
    """
    proxy._active_sse_streams.clear()
    principal = "principal-cancel"

    events: list[str] = []

    class _Upstream:
        status_code = 200

        async def aiter_bytes(self):
            # Yield one chunk so the generator starts, then hang so the task
            # can be cancelled while the generator is live.
            yield b"data: ok\n\n"
            await asyncio.sleep(10)

    class _StreamContext:
        async def __aenter__(self):
            return _Upstream()

        async def __aexit__(self, *_args: object):
            events.append("stream_exit")

    class _Client:
        def stream(self, *_args: object, **kwargs: object):
            return _StreamContext()

        async def aclose(self):
            events.append("client_closed")

    class _Httpx:
        @staticmethod
        def AsyncClient(**kwargs):
            return _Client()

        HTTPError = RuntimeError

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(proxy, "verify_access_token", lambda *_args: principal)
    monkeypatch.setattr(proxy, "_httpx_module", lambda: _Httpx)
    monkeypatch.setattr(
        proxy, "_streaming_response", lambda body, status_code: (body, status_code)
    )
    try:
        body, status = await proxy.sse_proxy(_AuthRequest(), "http://mnemos.test", "jwt")
        assert status == 200
        assert proxy._active_sse_streams.get(principal) == 1

        # Consume the first chunk (starts the generator and acquires the slot),
        # then cancel the iteration task so the generator's finally block runs
        # inside a cancelled task -- exactly the client-disconnect scenario.
        agen = body.__aiter__()
        first = asyncio.ensure_future(agen.__anext__())
        await asyncio.sleep(0)
        assert (await first) == b"data: ok\n\n"

        second = asyncio.ensure_future(agen.__anext__())
        await asyncio.sleep(0)
        second.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await second
    finally:
        monkeypatch.undo()

    assert "stream_exit" in events
    assert "client_closed" in events
    assert proxy._active_sse_streams.get(principal) in (None, 0)

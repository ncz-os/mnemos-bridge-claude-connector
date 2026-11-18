from __future__ import annotations

import asyncio
import contextlib
import math
import os
import threading
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import TYPE_CHECKING, Any

from .oauth import verify_access_token
from .redaction import install_httpx_log_redaction, redact_url_credentials

try:
    from fastapi import Request
    from starlette.responses import Response
except ModuleNotFoundError:
    if TYPE_CHECKING:
        from fastapi import Request
        from starlette.responses import Response


def _httpx_module() -> Any:
    try:
        import httpx
    except ModuleNotFoundError as exc:
        raise RuntimeError("httpx is required to proxy MCP traffic") from exc

    return httpx


def _json_response(
    payload: dict[str, str], status_code: int, headers: dict[str, str] | None = None
) -> Response:
    try:
        from fastapi.responses import JSONResponse
    except ModuleNotFoundError as exc:
        raise RuntimeError("fastapi is required to build proxy responses") from exc

    return JSONResponse(payload, status_code=status_code, headers=headers)


_DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024
_DEFAULT_MESSAGE_TIMEOUT_SECONDS = 30.0
_DEFAULT_SSE_IDLE_TIMEOUT_SECONDS = 300.0
_DEFAULT_MAX_STREAMS_PER_PRINCIPAL = 4
_HOP_BY_HOP_HEADERS = {
    "authorization",
    "connection",
    "content-length",
    "cookie",
    "forwarded",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
_FORWARDED_HEADER_PREFIX = "x-forwarded-"

_active_sse_streams: dict[str, int] = {}
_sse_streams_lock = threading.Lock()


class _PayloadTooLarge(Exception):
    pass


class UpstreamCredentialUnavailable(RuntimeError):
    pass


CredentialResolver = Callable[[str], Awaitable[str | None]]


install_httpx_log_redaction()


def _positive_int(raw: str | None) -> int | None:
    try:
        value = int(raw or "")
    except ValueError:
        return None
    return value if value > 0 else None


def _max_body_bytes() -> int:
    return _positive_int(os.getenv("CONNECTOR_MAX_BODY_BYTES")) or _DEFAULT_MAX_BODY_BYTES


def _message_timeout_seconds() -> float:
    try:
        value = float(os.getenv("CONNECTOR_MESSAGE_TIMEOUT_SECONDS", ""))
    except ValueError:
        return _DEFAULT_MESSAGE_TIMEOUT_SECONDS
    return value if math.isfinite(value) and value > 0 else _DEFAULT_MESSAGE_TIMEOUT_SECONDS


def _sse_idle_timeout_seconds() -> float:
    try:
        value = float(os.getenv("CONNECTOR_SSE_IDLE_TIMEOUT_SECONDS", ""))
    except ValueError:
        return _DEFAULT_SSE_IDLE_TIMEOUT_SECONDS
    return value if math.isfinite(value) and value > 0 else _DEFAULT_SSE_IDLE_TIMEOUT_SECONDS


def _max_streams_per_principal() -> int:
    return _positive_int(os.getenv("CONNECTOR_MAX_STREAMS_PER_PRINCIPAL")) or (
        _DEFAULT_MAX_STREAMS_PER_PRINCIPAL
    )


async def _try_acquire_sse_slot(principal: str) -> bool:
    limit = _max_streams_per_principal()
    with _sse_streams_lock:
        active = _active_sse_streams.get(principal, 0)
        if active >= limit:
            return False
        _active_sse_streams[principal] = active + 1
        return True


async def _release_sse_slot(principal: str) -> None:
    with _sse_streams_lock:
        active = _active_sse_streams.get(principal, 0)
        if active <= 0:
            # Defensive: the principal was never tracked or already fully
            # released; drop any stale entry and do not go negative.
            _active_sse_streams.pop(principal, None)
        elif active <= 1:
            _active_sse_streams.pop(principal, None)
        else:
            _active_sse_streams[principal] = active - 1


async def _read_body_limited(request: Request) -> bytes:
    max_bytes = _max_body_bytes()
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > max_bytes:
            raise _PayloadTooLarge
        body.extend(chunk)
    return bytes(body)


def _streaming_response(body: AsyncIterator[bytes], status_code: int) -> Response:
    try:
        from fastapi.responses import StreamingResponse
    except ModuleNotFoundError as exc:
        raise RuntimeError("fastapi is required to stream proxy responses") from exc

    return StreamingResponse(body, status_code=status_code, media_type="text/event-stream")


def _response(content: bytes, status_code: int, headers: dict[str, str]) -> Response:
    try:
        from fastapi.responses import Response
    except ModuleNotFoundError as exc:
        raise RuntimeError("fastapi is required to build proxy responses") from exc

    return Response(content=content, status_code=status_code, headers=headers)


def extract_bearer(request: Request) -> str | None:
    authorization = request.headers.get("authorization")
    if not authorization:
        return None

    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer":
        return None

    token = token.strip()
    return token or None


def _headers_with_swapped_authorization(request: Request, api_key: str) -> dict[str, str]:
    def _stripped(name: str) -> bool:
        lowered = name.lower()
        if lowered in _HOP_BY_HOP_HEADERS:
            return True
        return lowered.startswith(_FORWARDED_HEADER_PREFIX)

    headers = {name: value for name, value in request.headers.items() if not _stripped(name)}
    headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _unauthorized_response() -> Response:
    return _json_response({"error": "unauthorized"}, status_code=401)


async def _resolve_upstream_token(
    principal: str,
    resolver: CredentialResolver | None,
) -> str | None:
    if resolver is None:
        return principal
    return await resolver(principal)


async def sse_proxy(
    request: Request,
    backend_url: str,
    jwt_secret: str,
    credential_resolver: CredentialResolver | None = None,
) -> Response:
    token = extract_bearer(request)
    if token is None:
        return _unauthorized_response()

    principal = verify_access_token(token, jwt_secret)
    if principal is None:
        return _unauthorized_response()
    try:
        api_key = await _resolve_upstream_token(principal, credential_resolver)
    except UpstreamCredentialUnavailable as exc:
        return _json_response(
            {
                "error": "service_unavailable",
                "detail": redact_url_credentials(str(exc)),
            },
            status_code=503,
        )
    if api_key is None:
        return _unauthorized_response()

    if not await _try_acquire_sse_slot(principal):
        # Advise retry after the idle-timeout window, not a hard-coded 60s.
        retry_after = max(1, int(math.ceil(_sse_idle_timeout_seconds())))
        return _json_response(
            {"error": "too_many_streams"},
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )

    httpx = _httpx_module()
    # The SSE body is unbounded (read=None), so we do not set an overall client
    # timeout. Instead, the connection/handshake is bounded below with an
    # asyncio timeout, and each body read is guarded by the idle timeout inside
    # the generator.
    try:
        client = httpx.AsyncClient(timeout=None)
    except Exception:
        # The client was never constructed, so only the slot needs releasing.
        await _release_sse_slot(principal)
        raise
    stream_context = client.stream(
        "GET",
        f"{backend_url.rstrip('/')}/sse",
        headers=_headers_with_swapped_authorization(request, api_key),
    )

    # The HTTP client exists from construction onward, so it must always be
    # closed. ``stream_owned`` gates only the context-manager exit: the stream
    # context was never entered if ``__aenter__`` failed, and closing it
    # unconditionally would risk a double-exit or an error on a failed stream.
    stream_owned = False

    async def teardown() -> None:
        """Idempotent, cancellation-safe release of the upstream stream, the
        HTTP client, and the per-principal SSE slot.

        Every failure path funnels through this one place so cleanup is always
        applied together -- never partially -- and shielded so an in-flight
        cancellation cannot leave the stream or slot half-released.
        """
        if stream_owned:
            with contextlib.suppress(Exception):
                await asyncio.shield(stream_context.__aexit__(None, None, None))
        with contextlib.suppress(Exception):
            await asyncio.shield(client.aclose())
        await asyncio.shield(_release_sse_slot(principal))

    try:
        async with asyncio.timeout(_sse_idle_timeout_seconds()):
            upstream = await stream_context.__aenter__()
        stream_owned = True
    except httpx.HTTPError as exc:
        detail = redact_url_credentials(str(exc))
        await teardown()
        return _json_response(
            {"error": "bad_gateway", "detail": detail},
            status_code=502,
        )
    except BaseException:
        await teardown()
        raise

    async def body_iterator() -> AsyncIterator[bytes]:
        # Wrap only the read loop so an ``httpx.HTTPError`` raised inside
        # ``__anext__`` is caught here, not left to escape the loop body.
        # ``asyncio.timeout`` (TimeoutError) and ``StopAsyncIteration`` are
        # handled inside the loop and never reach this handler.
        idle_timeout = _sse_idle_timeout_seconds()
        upstream_iter = upstream.aiter_bytes()
        try:
            while True:
                try:
                    async with asyncio.timeout(idle_timeout):
                        chunk = await upstream_iter.__anext__()
                except TimeoutError:
                    return
                except StopAsyncIteration:
                    return
                yield chunk
        except httpx.HTTPError as exc:
            # Preserve the original exception (and its traceback) so network
            # failures stay debuggable; only the message is redacted.
            raise RuntimeError(redact_url_credentials(str(exc))) from exc
        finally:
            await teardown()

    try:
        return _streaming_response(body_iterator(), status_code=upstream.status_code)
    except BaseException:
        # StreamingResponse construction failed: the generator's finally will
        # never run, so release the slot and close resources here to avoid a
        # permanent leak.
        await teardown()
        raise


async def messages_proxy(
    request: Request,
    backend_url: str,
    jwt_secret: str,
    credential_resolver: CredentialResolver | None = None,
) -> Response:
    token = extract_bearer(request)
    if token is None:
        return _unauthorized_response()

    principal = verify_access_token(token, jwt_secret)
    if principal is None:
        return _unauthorized_response()
    try:
        api_key = await _resolve_upstream_token(principal, credential_resolver)
    except UpstreamCredentialUnavailable as exc:
        return _json_response(
            {
                "error": "service_unavailable",
                "detail": redact_url_credentials(str(exc)),
            },
            status_code=503,
        )
    if api_key is None:
        return _unauthorized_response()

    try:
        body = await _read_body_limited(request)
    except _PayloadTooLarge:
        return _json_response(
            {"error": "payload_too_large", "detail": "proxied MCP message body exceeds limit"},
            status_code=413,
        )

    httpx = _httpx_module()
    try:
        timeout = httpx.Timeout(_message_timeout_seconds())
        async with httpx.AsyncClient(timeout=timeout) as client:
            upstream = await client.post(
                f"{backend_url.rstrip('/')}/messages/",
                content=body,
                headers=_headers_with_swapped_authorization(request, api_key),
                params=request.query_params.multi_items(),
            )
    except httpx.HTTPError as exc:
        return _json_response(
            {"error": "bad_gateway", "detail": redact_url_credentials(str(exc))},
            status_code=502,
        )

    headers = {}
    content_type = upstream.headers.get("content-type")
    if content_type:
        headers["content-type"] = content_type

    return _response(content=upstream.content, status_code=upstream.status_code, headers=headers)


__all__ = ["UpstreamCredentialUnavailable", "extract_bearer", "messages_proxy", "sse_proxy"]

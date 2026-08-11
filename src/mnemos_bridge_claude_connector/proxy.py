from __future__ import annotations

import math
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import TYPE_CHECKING, Any

from .oauth import verify_access_token

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


def _json_response(payload: dict[str, str], status_code: int) -> Response:
    try:
        from fastapi.responses import JSONResponse
    except ModuleNotFoundError as exc:
        raise RuntimeError("fastapi is required to build proxy responses") from exc

    return JSONResponse(payload, status_code=status_code)


_DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024
_DEFAULT_MESSAGE_TIMEOUT_SECONDS = 30.0
_HOP_BY_HOP_HEADERS = {
    "authorization",
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class _PayloadTooLarge(Exception):
    pass


class UpstreamCredentialUnavailable(RuntimeError):
    pass


CredentialResolver = Callable[[str], Awaitable[str | None]]


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
    headers = {
        name: value
        for name, value in request.headers.items()
        if name.lower() not in _HOP_BY_HOP_HEADERS
    }
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
            {"error": "service_unavailable", "detail": str(exc)}, status_code=503
        )
    if api_key is None:
        return _unauthorized_response()

    httpx = _httpx_module()
    client = httpx.AsyncClient(timeout=None)
    stream_context = client.stream(
        "GET",
        f"{backend_url.rstrip('/')}/sse",
        headers=_headers_with_swapped_authorization(request, api_key),
    )

    try:
        upstream = await stream_context.__aenter__()
    except httpx.HTTPError as exc:
        await client.aclose()
        return _json_response({"error": "bad_gateway", "detail": str(exc)}, status_code=502)

    async def body_iterator() -> AsyncIterator[bytes]:
        try:
            async for chunk in upstream.aiter_bytes():
                yield chunk
        finally:
            await stream_context.__aexit__(None, None, None)
            await client.aclose()

    return _streaming_response(body_iterator(), status_code=upstream.status_code)


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
            {"error": "service_unavailable", "detail": str(exc)}, status_code=503
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
        return _json_response({"error": "bad_gateway", "detail": str(exc)}, status_code=502)

    headers = {}
    content_type = upstream.headers.get("content-type")
    if content_type:
        headers["content-type"] = content_type

    return _response(content=upstream.content, status_code=upstream.status_code, headers=headers)


__all__ = ["UpstreamCredentialUnavailable", "extract_bearer", "messages_proxy", "sse_proxy"]

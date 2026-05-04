from __future__ import annotations

from collections.abc import AsyncIterator
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
        if name.lower() != "authorization"
    }
    headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _unauthorized_response() -> Response:
    return _json_response({"error": "unauthorized"}, status_code=401)


async def sse_proxy(request: Request, backend_url: str, jwt_secret: str) -> Response:
    token = extract_bearer(request)
    if token is None:
        return _unauthorized_response()

    api_key = verify_access_token(token, jwt_secret)
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


async def messages_proxy(request: Request, backend_url: str, jwt_secret: str) -> Response:
    token = extract_bearer(request)
    if token is None:
        return _unauthorized_response()

    api_key = verify_access_token(token, jwt_secret)
    if api_key is None:
        return _unauthorized_response()

    body = await request.body()
    httpx = _httpx_module()
    try:
        async with httpx.AsyncClient(timeout=None) as client:
            upstream = await client.post(
                f"{backend_url.rstrip('/')}/messages/",
                content=body,
                headers=_headers_with_swapped_authorization(request, api_key),
            )
    except httpx.HTTPError as exc:
        return _json_response({"error": "bad_gateway", "detail": str(exc)}, status_code=502)

    headers = {}
    content_type = upstream.headers.get("content-type")
    if content_type:
        headers["content-type"] = content_type

    return _response(content=upstream.content, status_code=upstream.status_code, headers=headers)


__all__ = ["extract_bearer", "messages_proxy", "sse_proxy"]

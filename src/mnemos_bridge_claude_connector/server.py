from __future__ import annotations

import html
import logging
import os
from collections.abc import Callable
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .oauth import (
    consume_code,
    exchange_refresh_token,
    generate_code,
    issue_access_token,
)
from .proxy import messages_proxy, sse_proxy

try:
    from fastapi import FastAPI as _FastAPI
    from fastapi import Request
    from starlette.responses import Response
except ModuleNotFoundError:
    _FastAPI = None
    if TYPE_CHECKING:
        from fastapi import Request
        from starlette.responses import Response


_LEGACY_BACKEND_URL = os.getenv("MNEMOS_BACKEND_URL", "").rstrip("/")
MNEMOS_API_URL = (
    os.getenv("MNEMOS_API_URL", "").rstrip("/")
    or _LEGACY_BACKEND_URL
    or "http://192.168.207.67:5002"
)
MNEMOS_MCP_URL = (
    os.getenv("MNEMOS_MCP_URL", "").rstrip("/")
    or _LEGACY_BACKEND_URL
    or "http://192.168.207.67:5003"
)
# Compatibility alias for callers that imported the old setting directly.
MNEMOS_BACKEND_URL = MNEMOS_MCP_URL
CONNECTOR_BIND = os.getenv("CONNECTOR_BIND", "127.0.0.1:8089")
CONNECTOR_PUBLIC_URL = os.getenv("CONNECTOR_PUBLIC_URL", "http://localhost:8089").rstrip("/")
_DEFAULT_ALLOWED_REDIRECT_URIS = ("https://claude.ai/api/mcp/auth_callback",)
_MIN_JWT_SECRET_LENGTH = 32
_TRUTHY = {"1", "true", "yes", "on"}
logger = logging.getLogger(__name__)


class MnemosValidationUnavailable(RuntimeError):
    pass


def _env_truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in _TRUTHY


def _require_jwt_secret() -> str:
    secret = os.getenv("CONNECTOR_JWT_SECRET", "")
    if not secret:
        raise RuntimeError("CONNECTOR_JWT_SECRET is required")
    if len(secret) < _MIN_JWT_SECRET_LENGTH and not _env_truthy("CONNECTOR_ALLOW_WEAK_JWT_SECRET"):
        raise RuntimeError(
            "CONNECTOR_JWT_SECRET must be at least 32 characters; "
            "set CONNECTOR_ALLOW_WEAK_JWT_SECRET=1 only for isolated tests"
        )
    return secret


CONNECTOR_JWT_SECRET = _require_jwt_secret()


RouteDecorator = Callable[[Callable[..., Any]], Callable[..., Any]]


class _MissingDependencyApp:
    def get(self, *_args: Any, **_kwargs: Any) -> RouteDecorator:
        return lambda handler: handler

    def post(self, *_args: Any, **_kwargs: Any) -> RouteDecorator:
        return lambda handler: handler


def _build_app() -> Any:
    if _FastAPI is None:
        return _MissingDependencyApp()

    return _FastAPI(title="MNEMOS Claude Connector", version="0.1.0")


app = _build_app()

_AUTHORIZE_FORM_FIELDS = (
    "client_id",
    "redirect_uri",
    "state",
    "code_challenge",
    "code_challenge_method",
    "response_type",
)


def _url(path: str) -> str:
    return f"{CONNECTOR_PUBLIC_URL}{path}"


def _oauth_metadata() -> dict[str, object]:
    return {
        "issuer": CONNECTOR_PUBLIC_URL,
        "authorization_endpoint": _url("/oauth/authorize"),
        "token_endpoint": _url("/oauth/token"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }


def _html_attr(value: object) -> str:
    return html.escape(str(value), quote=True)


def _hidden_input(name: str, value: str) -> str:
    return f'<input type="hidden" name="{_html_attr(name)}" value="{_html_attr(value)}">'


def _render_authorize_form(
    params: dict[str, str],
    *,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    try:
        from fastapi.responses import HTMLResponse
    except ModuleNotFoundError as exc:
        raise RuntimeError("fastapi is required to render authorization pages") from exc

    hidden_inputs = "\n".join(
        _hidden_input(name, params.get(name, "")) for name in _AUTHORIZE_FORM_FIELDS
    )
    error_markup = ""
    if error:
        error_markup = f'<p role="alert" style="color: #b00020;">{html.escape(error)}</p>'

    return HTMLResponse(
        f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Authorize Claude</title>
  </head>
  <body>
    <main>
      <h1>Authorize Claude</h1>
      {error_markup}
      <form method="post" action="/oauth/authorize">
        {hidden_inputs}
        <label for="mnemos_api_key">MNEMOS API Key</label>
        <input
          id="mnemos_api_key"
          name="mnemos_api_key"
          type="text"
          autocomplete="off"
          required
        >
        <button type="submit">Authorize Claude</button>
      </form>
    </main>
  </body>
</html>""",
        status_code=status_code,
    )


def _request_params(request: Request) -> dict[str, str]:
    return {name: request.query_params.get(name, "") for name in _AUTHORIZE_FORM_FIELDS}


def _form_params(form: Any) -> dict[str, str]:
    return {name: str(form.get(name, "")) for name in _AUTHORIZE_FORM_FIELDS}


def _redirect_uri_with_oauth_params(redirect_uri: str, code: str, state: str) -> str:
    parsed = urlsplit(redirect_uri)
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    query_items.append(("code", code))
    query_items.append(("state", state))
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(query_items),
            parsed.fragment,
        )
    )


def _configured_allowed_redirect_uris() -> tuple[str, ...]:
    raw = os.getenv("CONNECTOR_ALLOWED_REDIRECT_URIS", "")
    values = tuple(part.strip() for part in raw.split(",") if part.strip())
    return values or _DEFAULT_ALLOWED_REDIRECT_URIS


def _normalise_redirect_uri(redirect_uri: str) -> str | None:
    try:
        parsed = urlsplit(redirect_uri)
        port = parsed.port
    except ValueError:
        return None
    if not parsed.scheme or not parsed.netloc or parsed.fragment:
        return None
    if parsed.username or parsed.password:
        return None

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return None
    if scheme != "https" and not (scheme == "http" and hostname in {"localhost", "127.0.0.1", "::1"}):
        return None

    if ":" in hostname and not hostname.startswith("["):
        netloc = f"[{hostname}]"
    else:
        netloc = hostname
    if port is not None:
        netloc = f"{netloc}:{port}"

    return urlunsplit((scheme, netloc, parsed.path or "", parsed.query, ""))


def _redirect_uri_allowed(redirect_uri: str) -> bool:
    normalised = _normalise_redirect_uri(redirect_uri)
    if normalised is None:
        return False
    allowed = {
        value
        for uri in _configured_allowed_redirect_uris()
        if (value := _normalise_redirect_uri(uri)) is not None
    }
    return normalised in allowed


def _oauth_error(error: str, description: str, status_code: int = 400) -> Response:
    try:
        from fastapi.responses import JSONResponse
    except ModuleNotFoundError as exc:
        raise RuntimeError("fastapi is required to build OAuth error responses") from exc

    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def _token_response(access_token: str, refresh_token: str) -> Response:
    try:
        from fastapi.responses import JSONResponse
    except ModuleNotFoundError as exc:
        raise RuntimeError("fastapi is required to build OAuth token responses") from exc

    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": refresh_token,
        },
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


async def validate_mnemos_api_key(api_key: str) -> bool:
    if not api_key:
        return False

    try:
        import httpx
    except ModuleNotFoundError as exc:
        raise RuntimeError("httpx is required to validate MNEMOS API keys") from exc

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{MNEMOS_API_URL}/auth/oauth/me",
                headers={"Authorization": f"Bearer {api_key}"},
            )
    except httpx.HTTPError as exc:
        raise MnemosValidationUnavailable("MNEMOS API key validation is unavailable") from exc

    if response.status_code in {401, 403}:
        return False
    if response.status_code != 200:
        raise MnemosValidationUnavailable(
            f"MNEMOS API key validation returned HTTP {response.status_code}"
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise MnemosValidationUnavailable(
            "MNEMOS API key validation returned an invalid response"
        ) from exc
    return payload.get("authenticated") is True and bool(payload.get("user_id"))


def _mcp_token_for_api_key(api_key: str) -> str | None:
    raw_map = os.getenv("MNEMOS_MCP_TOKENS", "").strip()
    if raw_map:
        for item in raw_map.split(","):
            parts = [part.strip() for part in item.strip().split(":", 2)]
            if len(parts) == 2 and parts[0] and parts[1] and api_key == parts[1]:
                return parts[1]
            if len(parts) == 3 and all(parts) and api_key == parts[2]:
                return parts[1]
        return None

    return os.getenv("MNEMOS_MCP_TOKEN", "").strip() or None


@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server_metadata() -> dict[str, object]:
    return _oauth_metadata()


@app.get("/.well-known/openid-configuration")
async def openid_configuration() -> dict[str, object]:
    metadata = _oauth_metadata()
    metadata.update(
        {
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["HS256"],
        }
    )
    return metadata


@app.get("/oauth/authorize")
async def oauth_authorize_get(request: Request) -> Response:
    params = _request_params(request)
    if not params["client_id"].strip():
        return _render_authorize_form(
            params,
            error="Missing client_id. Please try again.",
            status_code=400,
        )
    return _render_authorize_form(params)


@app.post("/oauth/authorize")
async def oauth_authorize_post(request: Request) -> Response:
    form = await request.form()
    params = _form_params(form)
    api_key = str(form.get("mnemos_api_key", "")).strip()

    if not params["client_id"].strip():
        return _render_authorize_form(
            params,
            error="Missing client_id. Please try again.",
            status_code=400,
        )

    if params["response_type"] != "code":
        return _render_authorize_form(
            params,
            error="Unsupported response_type. Please try again.",
            status_code=400,
        )

    if not params["redirect_uri"]:
        return _render_authorize_form(
            params,
            error="Missing redirect_uri. Please try again.",
            status_code=400,
        )

    if not _redirect_uri_allowed(params["redirect_uri"]):
        return _render_authorize_form(
            params,
            error="Unsupported redirect_uri. Please ask the connector operator to allow it.",
            status_code=400,
        )

    if not params["code_challenge"] or params["code_challenge_method"] != "S256":
        return _render_authorize_form(
            params,
            error="Invalid PKCE challenge. Please try again.",
            status_code=400,
        )

    try:
        key_is_valid = await validate_mnemos_api_key(api_key)
    except MnemosValidationUnavailable:
        logger.exception("MNEMOS API key validation failed")
        return _render_authorize_form(
            params,
            error="MNEMOS is temporarily unavailable. Please try again later.",
            status_code=503,
        )

    if not key_is_valid:
        return _render_authorize_form(params, error="Invalid API key. Please try again.")

    mcp_token = _mcp_token_for_api_key(api_key)
    if mcp_token is None:
        return _render_authorize_form(
            params,
            error="This API key is not provisioned for MCP access.",
            status_code=403,
        )

    code = generate_code(
        mcp_token,
        params["client_id"],
        params["code_challenge"],
        params["code_challenge_method"],
        params["redirect_uri"],
    )
    location = _redirect_uri_with_oauth_params(params["redirect_uri"], code, params["state"])
    try:
        from fastapi.responses import RedirectResponse
    except ModuleNotFoundError as exc:
        raise RuntimeError("fastapi is required to build authorization redirects") from exc

    return RedirectResponse(location, status_code=302)


@app.post("/oauth/token")
async def oauth_token(request: Request) -> Response:
    form = await request.form()
    grant_type = str(form.get("grant_type", ""))

    if grant_type == "authorization_code":
        code = str(form.get("code", ""))
        code_verifier = str(form.get("code_verifier", ""))
        redirect_uri = str(form.get("redirect_uri", ""))
        client_id = str(form.get("client_id", ""))
        if not code or not code_verifier or not redirect_uri or not client_id:
            return _oauth_error(
                "invalid_request",
                "Missing code, code_verifier, redirect_uri, or client_id.",
            )

        api_key = consume_code(code, code_verifier, redirect_uri, client_id)
        if api_key is None:
            return _oauth_error(
                "invalid_grant",
                "Invalid authorization code, expired code, or PKCE verifier.",
            )

        access_token, refresh_token = issue_access_token(api_key, CONNECTOR_JWT_SECRET)
        return _token_response(access_token, refresh_token)

    if grant_type == "refresh_token":
        refresh_token = str(form.get("refresh_token", ""))
        if not refresh_token:
            return _oauth_error("invalid_request", "Missing refresh_token.")

        exchanged = exchange_refresh_token(refresh_token, CONNECTOR_JWT_SECRET)
        if exchanged is None:
            return _oauth_error("invalid_grant", "Invalid refresh_token.")

        access_token, new_refresh_token = exchanged
        return _token_response(access_token, new_refresh_token)

    return _oauth_error("unsupported_grant_type", "Unsupported grant_type.")


@app.get("/sse")
async def sse(request: Request) -> Response:
    return await sse_proxy(request, MNEMOS_MCP_URL, CONNECTOR_JWT_SECRET)


@app.post("/messages/")
async def messages(request: Request) -> Response:
    return await messages_proxy(request, MNEMOS_MCP_URL, CONNECTOR_JWT_SECRET)


def _parse_bind(bind: str) -> tuple[str, int]:
    host, separator, port_text = bind.rpartition(":")
    if not separator:
        raise ValueError("CONNECTOR_BIND must be formatted as host:port")
    return host or "0.0.0.0", int(port_text)


def main() -> None:
    try:
        import uvicorn
    except ModuleNotFoundError as exc:
        raise RuntimeError("uvicorn is required to run the connector server") from exc

    host, port = _parse_bind(CONNECTOR_BIND)
    uvicorn.run("mnemos_bridge_claude_connector.server:app", host=host, port=port)


if __name__ == "__main__":
    main()

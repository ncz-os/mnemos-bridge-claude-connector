# mnemos-bridge-claude-connector

`mnemos-bridge-claude-connector` is an OAuth-fronted MCP adapter for Claude.ai
Connectors. It lets Claude.ai authenticate users through an OAuth 2.1
authorization-code flow while the adapter proxies MCP traffic to a MNEMOS
deployment using each user's pre-issued MNEMOS API key.

The operator issues MNEMOS API keys to users. During connector authorization,
the user pastes that API key into the adapter's `/oauth/authorize` page. The
adapter validates the key against MNEMOS, exchanges a PKCE-protected
authorization code for a JWT access token, and then uses the MNEMOS API key
claim from that JWT as the upstream bearer token for MCP proxy requests.

## Prerequisites

- A running MNEMOS REST API and MCP HTTP server. They are separate MNEMOS
  applications and default to PYTHIA ports `5002` and `5003`, respectively.
- MCP bearer credentials provisioned identically in the connector and MCP
  server through per-user `MNEMOS_MCP_TOKENS`, or through `MNEMOS_MCP_TOKEN`
  plus `CONNECTOR_SINGLE_USER_API_KEY` for an explicit single-user deployment.
- A strong `CONNECTOR_JWT_SECRET` value with at least 32 characters.
- TLS termination for production OAuth traffic. Terminate HTTPS in front of this
  service with nginx or an equivalent reverse proxy.

## Installation

```bash
pip install mnemos-bridge-claude-connector
```

## Configuration

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `MNEMOS_API_URL` | No | `http://192.168.207.67:5002` | Base URL for the MNEMOS REST API used to validate user API keys. |
| `MNEMOS_MCP_URL` | No | `http://192.168.207.67:5003` | Base URL for the MNEMOS MCP HTTP/SSE server started by `mnemos serve mcp-http`. |
| `MNEMOS_BACKEND_URL` | No | None | Deprecated compatibility setting used for both URLs when the deployment combines both applications behind one path-routing proxy. Explicit API and MCP URLs take precedence. |
| `MNEMOS_MCP_TOKEN` | Single-user mode only | None | Shared bearer token configured on the MNEMOS MCP server. Requires `CONNECTOR_SINGLE_USER_API_KEY`; other valid MNEMOS users are rejected. |
| `MNEMOS_MCP_TOKENS` | One MCP token setting is required | None | Per-user MCP mapping in the MNEMOS server's `user_id:api_key` or `user_id:mcp_token:api_key` format. The connector accepts authorization only for API keys in this map. |
| `CONNECTOR_SINGLE_USER_API_KEY` | Required with `MNEMOS_MCP_TOKEN` | None | The one MNEMOS API key allowed to authorize in shared-token mode. Do not set this in per-user mode. |
| `CONNECTOR_JWT_SECRET` | Yes | None | HS256 signing secret for connector access tokens. |
| `CONNECTOR_BIND` | No | `127.0.0.1:8089` | Host and port used by `mnemos-claude-connector`. Bind an explicit non-loopback address only behind TLS/reverse-proxy controls. |
| `CONNECTOR_PUBLIC_URL` | No | `http://localhost:8089` | Public issuer and endpoint base URL advertised to Claude.ai. |
| `CONNECTOR_ALLOWED_REDIRECT_URIS` | No | `https://claude.ai/api/mcp/auth_callback` | Comma-separated exact OAuth redirect URI allowlist. Loopback HTTP is allowed for local testing; production redirects should be HTTPS. |
| `CONNECTOR_MAX_BODY_BYTES` | No | `5242880` | Maximum proxied `/messages/` request body size. |
| `CONNECTOR_MESSAGE_TIMEOUT_SECONDS` | No | `30` | Connect, read, write, and connection-pool timeout for proxied `/messages/` requests. SSE reads remain unlimited. |
| `CONNECTOR_REFRESH_TOKEN_TTL_SECONDS` | No | `2592000` | Refresh-token lifetime. |
| `CONNECTOR_TOKEN_STORE_PATH` | No | `$XDG_STATE_HOME/mnemos-bridge-claude-connector/oauth.sqlite3`, or `~/.local/state/mnemos-bridge-claude-connector/oauth.sqlite3` | SQLite TTL store for authorization codes, access-token mappings, and refresh tokens. Use a persistent local volume. All connector workers on a host must use the same path. |

## Running

```bash
export CONNECTOR_JWT_SECRET='replace-with-a-long-random-secret'
export CONNECTOR_PUBLIC_URL='https://mnemos-connector.example.com'
export CONNECTOR_ALLOWED_REDIRECT_URIS='https://claude.ai/api/mcp/auth_callback'
export MNEMOS_API_URL='http://127.0.0.1:5002'
export MNEMOS_MCP_URL='http://127.0.0.1:5003'
export MNEMOS_MCP_TOKENS='user1:mcp-token-for-user1:mnemos-api-key-for-user1'
mnemos-claude-connector
```

## Claude.ai Connector Registration

Register the connector in Claude.ai with:

- Connector URL: `CONNECTOR_PUBLIC_URL`
- OAuth metadata URL:
  `CONNECTOR_PUBLIC_URL/.well-known/oauth-authorization-server`

After registration, Claude.ai will open the adapter's authorization page. Users
paste their MNEMOS API key, approve access, and Claude.ai receives OAuth tokens
that are scoped to the MNEMOS API key they supplied.

## Security Considerations

- Authorization codes, opaque access-token mappings, and refresh tokens are
  stored in a mode-`0600` SQLite database. The default survives process restarts
  and is shared safely by workers on one host. Put
  `CONNECTOR_TOKEN_STORE_PATH` on persistent storage. Replicas on different
  hosts must share that path through an appropriate filesystem or be kept
  session-affine; SQLite does not provide a distributed token store.
- Keep `CONNECTOR_JWT_SECRET` private and rotate it according to your operator
  policy. Rotating the secret invalidates existing access tokens.
- Keep `CONNECTOR_ALLOWED_REDIRECT_URIS` narrow. Authorization codes are issued
  only to exact allowlisted redirect URIs so a malicious OAuth client cannot
  receive a code for a user-entered MNEMOS API key.
- Run behind HTTPS in production. OAuth redirects and bearer tokens must not
  traverse public networks over plain HTTP.

## Build infrastructure & partners

Continuous integration and package distribution for this project are generously
supported by our open-source infrastructure partners:

- **[GitLab](https://gitlab.com/)** — canonical source hosting and CI pipelines
  (format / lint / test gates), via the
  [GitLab for Open Source](https://about.gitlab.com/solutions/open-source/) program.
- **[Buildkite](https://buildkite.com/)** — CI/CD orchestration with hosted macOS
  and Linux agents, and our APT package registry host
  (`packages.buildkite.com/ncz-os/ncz`), via the
  [Buildkite Open Source](https://buildkite.com/pricing) program.

Thank you to both for backing open-source software.

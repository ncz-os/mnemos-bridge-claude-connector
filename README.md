# ⚠️ This is a mirror — the canonical repo lives on GitLab

### 👉 https://gitlab.com/ncz-os/mnemos-bridge-claude-connector

**Source, releases, issues, merge requests, and CI all live on GitLab.** This GitHub copy is a read-only mirror and may lag. Please file issues and get releases there.

---

> # 📍 Moved to GitLab
> **The canonical, authoritative home of this project is GitLab — always:**
> ## 👉 https://gitlab.com/ncz-os/mnemos-bridge-claude-connector
>
> This GitHub repository is a **frozen, read-only mirror**. All development, issues, and releases happen on GitLab. Please open issues and merge requests there. The full history of this stub is preserved on GitLab.

---

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

- A running MNEMOS MCP server. The default backend URL targets PYTHIA on port
  `5003`.
- A strong `CONNECTOR_JWT_SECRET` value.
- TLS termination for production OAuth traffic. Terminate HTTPS in front of this
  service with nginx or an equivalent reverse proxy.

## Installation

```bash
pip install mnemos-bridge-claude-connector
```

## Configuration

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `MNEMOS_BACKEND_URL` | No | `http://192.168.207.67:5003` | Base URL for the MNEMOS MCP server. |
| `CONNECTOR_JWT_SECRET` | Yes | None | HS256 signing secret for connector access tokens. |
| `CONNECTOR_BIND` | No | `0.0.0.0:8089` | Host and port used by `mnemos-claude-connector`. |
| `CONNECTOR_PUBLIC_URL` | No | `http://localhost:8089` | Public issuer and endpoint base URL advertised to Claude.ai. |

## Running

```bash
export CONNECTOR_JWT_SECRET='replace-with-a-long-random-secret'
export CONNECTOR_PUBLIC_URL='https://mnemos-connector.example.com'
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

- Authorization codes and refresh tokens are stored in memory. This is suitable
  only for a single adapter instance. For high availability or multi-instance
  deployments, replace the in-memory stores with Redis or another shared
  backend.
- Keep `CONNECTOR_JWT_SECRET` private and rotate it according to your operator
  policy. Rotating the secret invalidates existing access tokens.
- Run behind HTTPS in production. OAuth redirects and bearer tokens must not
  traverse public networks over plain HTTP.

## Known Limitations

- Refresh tokens do not expire in v0.1.
- The in-memory token store is lost when the process restarts.
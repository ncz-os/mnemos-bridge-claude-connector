# Changelog

## Unreleased

- SSE hardening (NG2-BR-016): per-principal concurrent `/sse` stream caps (`CONNECTOR_MAX_STREAMS_PER_PRINCIPAL`, default 4) with `429` and a fixed advisory `Retry-After` hint; `CONNECTOR_SSE_IDLE_TIMEOUT_SECONDS` (default 300) now bounds both the per-read idle window and the upstream handshake (slow connects fail with `502` instead of hanging); unified cancellation-safe teardown that releases the upstream stream, the HTTP client, and the principal's slot together (shielded cleanup coroutine, no retry loop); `cookie`/`forwarded`/`x-forwarded-*` header stripping; and cause-chain-preserving error redaction.

## v0.1.0

- Initial release of the OAuth-fronted MNEMOS MCP adapter for Claude.ai Connectors.
- Added OAuth 2.1 authorization-code and refresh-token flows with S256 PKCE.
- Added JWT bearer validation and MCP `/sse` plus `/messages/` proxy endpoints.

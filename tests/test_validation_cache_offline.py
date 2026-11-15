from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

os.environ["CONNECTOR_JWT_SECRET"] = "offline-test-secret-with-enough-entropy"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mnemos_bridge_claude_connector import server as server_module


@pytest.fixture(autouse=True)
def _clean_cache(monkeypatch: pytest.MonkeyPatch):
    server_module._validation_cache_invalidate_for_test()
    monkeypatch.delenv("MNEMOS_MCP_TOKENS", raising=False)
    monkeypatch.delenv("MNEMOS_MCP_TOKEN", raising=False)
    monkeypatch.delenv("CONNECTOR_SINGLE_USER_API_KEY", raising=False)
    monkeypatch.setenv("MNEMOS_MCP_TOKENS", "test-user:mcp-token:api-key-1")
    yield
    server_module._validation_cache_invalidate_for_test()


async def test_repeated_validations_hit_cache_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    async def live_validate(api_key: str) -> bool:
        nonlocal calls
        calls += 1
        return True

    monkeypatch.setattr(server_module, "validate_mnemos_api_key", live_validate)

    for _ in range(5):
        assert await server_module._validated_mcp_token("api-key-1") == "mcp-token"

    assert calls == 1


async def test_invalid_result_is_never_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    async def live_validate(api_key: str) -> bool:
        nonlocal calls
        calls += 1
        return False

    monkeypatch.setattr(server_module, "validate_mnemos_api_key", live_validate)

    for _ in range(3):
        assert await server_module._validated_mcp_token("revoked-key") is None

    assert calls == 3


async def test_cache_expiry_revalidates(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    async def live_validate(api_key: str) -> bool:
        nonlocal calls
        calls += 1
        return True

    monkeypatch.setattr(server_module, "validate_mnemos_api_key", live_validate)

    assert await server_module._validated_mcp_token("api-key-1") == "mcp-token"
    assert calls == 1

    # Force expiry of the cached entry.
    digest = server_module._validation_cache_key("api-key-1")
    server_module._validation_cache[digest] = 0.0

    assert await server_module._validated_mcp_token("api-key-1") == "mcp-token"
    assert calls == 2


async def test_validation_unavailable_is_never_cached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    async def flaky_validate(api_key: str) -> bool:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise server_module.MnemosValidationUnavailable("blip")
        return True

    monkeypatch.setattr(server_module, "validate_mnemos_api_key", flaky_validate)

    with pytest.raises(server_module.UpstreamCredentialUnavailable):
        await server_module._validated_mcp_token("api-key-1")
    assert await server_module._validated_mcp_token("api-key-1") == "mcp-token"
    assert calls == 2


async def test_uncached_revocation_evicts_stale_positive_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {"valid": True}
    calls = 0

    async def live_validate(api_key: str) -> bool:
        nonlocal calls
        calls += 1
        return state["valid"]

    monkeypatch.setattr(server_module, "validate_mnemos_api_key", live_validate)

    # Proxy path populates the cache.
    assert await server_module._validated_mcp_token("api-key-1") == "mcp-token"
    assert calls == 1

    # Key revoked upstream; token/refresh path revalidates uncached and must
    # evict the stale positive entry.
    state["valid"] = False
    assert (
        await server_module._validated_mcp_token("api-key-1", _uncached=True) is None
    )
    assert calls == 2

    # Proxy path must revalidate, not serve the stale entry.
    assert await server_module._validated_mcp_token("api-key-1") is None
    assert calls == 3


async def test_cache_key_is_sha256_not_cleartext() -> None:
    import hashlib

    assert server_module._validation_cache_key("api-key-1") == hashlib.sha256(
        b"api-key-1"
    ).hexdigest()
    for digest in server_module._validation_cache:
        assert "api-key" not in digest

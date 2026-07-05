from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


os.environ["CONNECTOR_JWT_SECRET"] = "offline-test-secret-with-enough-entropy"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mnemos_bridge_claude_connector import proxy  # noqa: E402


class _HeaderRequest:
    headers = {
        "authorization": "Bearer connector-token",
        "host": "attacker.example",
        "content-length": "999",
        "connection": "keep-alive",
        "accept": "text/event-stream",
        "x-request-id": "req-1",
    }


class _StreamRequest:
    headers = {}

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def stream(self):
        for chunk in self._chunks:
            yield chunk


def test_headers_with_swapped_authorization_drops_hop_by_hop_headers() -> None:
    headers = proxy._headers_with_swapped_authorization(_HeaderRequest(), "mnemos-key")

    assert headers == {
        "accept": "text/event-stream",
        "x-request-id": "req-1",
        "Authorization": "Bearer mnemos-key",
    }


@pytest.mark.asyncio
async def test_read_body_limited_rejects_oversized_message(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONNECTOR_MAX_BODY_BYTES", "4")

    with pytest.raises(proxy._PayloadTooLarge):
        await proxy._read_body_limited(_StreamRequest([b"ab", b"cd", b"e"]))


@pytest.mark.asyncio
async def test_read_body_limited_allows_exact_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONNECTOR_MAX_BODY_BYTES", "4")

    assert await proxy._read_body_limited(_StreamRequest([b"ab", b"cd"])) == b"abcd"

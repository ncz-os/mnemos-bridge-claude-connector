"""Regression test for NG2-BR-013: OAuth store must not leak sqlite connections.

Fails on the old code (connection never closed -> ResourceWarning under
-W error::ResourceWarning, fd count grows); passes on the fix.
"""

from __future__ import annotations

import os
import sys
import tempfile
import warnings
from pathlib import Path

os.environ["CONNECTOR_TOKEN_STORE_PATH"] = os.path.join(
    tempfile.gettempdir(), f"mnemos-connector-oauth-leak-{os.getpid()}.sqlite3"
)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mnemos_bridge_claude_connector import oauth  # noqa: E402


JWT_SECRET = "leak-test-secret-with-enough-entropy-for-hs256"


def _fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


def test_verify_access_token_does_not_leak_connections_or_fds() -> None:
    token, _ = oauth.issue_access_token("leak-api-key", JWT_SECRET)
    assert oauth.verify_access_token(token, JWT_SECRET) == "leak-api-key"

    baseline = _fd_count()
    with warnings.catch_warnings():
        warnings.simplefilter("error", ResourceWarning)
        for _ in range(200):
            assert oauth.verify_access_token(token, JWT_SECRET) == "leak-api-key"
    assert _fd_count() <= baseline


def test_schema_ddl_runs_once_per_path() -> None:
    import threading
    from unittest.mock import patch

    ddl_count = {"count": 0}
    count_lock = threading.Lock()
    real_ensure = oauth._ensure_schema

    def counting_ensure(connection):
        with count_lock:
            ddl_count["count"] += 1
        return real_ensure(connection)

    with patch.object(oauth, "_ensure_schema", counting_ensure):
        oauth._initialized_paths.clear()
        token, _ = oauth.issue_access_token("ddl-api-key", JWT_SECRET)
        # Concurrent first-touch: DDL must still run exactly once.
        barrier = threading.Barrier(8)
        errors: list[BaseException] = []

        def hammer():
            try:
                barrier.wait(timeout=10)
                for _ in range(5):
                    oauth.verify_access_token(token, JWT_SECRET)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=hammer) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert not errors
        assert ddl_count["count"] == 1


def test_concurrent_first_touch_never_sees_missing_table(tmp_path) -> None:
    """Concurrent uninitialized first-touch must never raise 'no such table'.

    Guards the NG2-BR-013 follow-up race: initialization (file setup + DDL +
    marking the path initialized) must complete under a single lock before any
    connection is yielded, so no thread can observe a schema-less connection.
    """
    import threading

    store = tmp_path / "concurrent-first-touch.sqlite3"
    monkey_path = str(store)
    real_store_path = oauth._store_path

    def patched_store_path() -> Path:
        return Path(monkey_path)

    oauth._store_path = patched_store_path  # type: ignore[method-assign]
    oauth._initialized_paths.discard(monkey_path)
    try:
        barrier = threading.Barrier(16)
        errors: list[BaseException] = []

        def hammer() -> None:
            try:
                barrier.wait(timeout=10)
                with oauth._connect() as connection:
                    connection.execute("SELECT COUNT(*) FROM connector_oauth_entries").fetchone()
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=hammer) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert not [thread for thread in threads if thread.is_alive()]
        assert not errors, [str(error) for error in errors]
        with oauth._connect() as connection:
            connection.execute("SELECT COUNT(*) FROM connector_oauth_entries").fetchone()
    finally:
        oauth._store_path = real_store_path  # type: ignore[method-assign]
        oauth._initialized_paths.discard(monkey_path)
    import threading
    from unittest.mock import patch

    ddl_count = {"count": 0}
    count_lock = threading.Lock()
    real_ensure = oauth._ensure_schema

    def counting_ensure(connection):
        with count_lock:
            ddl_count["count"] += 1
        return real_ensure(connection)

    with patch.object(oauth, "_ensure_schema", counting_ensure):
        oauth._initialized_paths.clear()
        token, _ = oauth.issue_access_token("ddl-api-key", JWT_SECRET)
        # Concurrent first-touch: DDL must still run exactly once.
        barrier = threading.Barrier(8)
        errors: list[BaseException] = []

        def hammer():
            try:
                barrier.wait(timeout=10)
                for _ in range(5):
                    oauth.verify_access_token(token, JWT_SECRET)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=hammer) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert not errors
        assert ddl_count["count"] == 1

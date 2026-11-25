from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mnemos_bridge_claude_connector import redaction


@pytest.fixture
def httpx_logger():
    logger = logging.getLogger("httpx")
    handlers = logger.handlers[:]
    filters = logger.filters[:]
    propagate = logger.propagate
    logger.handlers.clear()
    logger.filters.clear()
    logger.propagate = False
    try:
        yield logger
    finally:
        logger.handlers[:] = handlers
        logger.filters[:] = filters
        logger.propagate = propagate


def test_removes_userinfo() -> None:
    assert redaction.redact_url_credentials("https://user:pw@host/p") == "https://host/p"


@pytest.mark.parametrize(
    "name",
    ["api_key", "apikey", "auth", "authorization", "bearer", "jwt", "key", "sig"],
)
def test_redacts_sensitive_query_names(name: str) -> None:
    url = f"https://host/p?{name}=example"
    assert redaction.redact_url_credentials(url) == f"https://host/p?{name}=***REDACTED***"


@pytest.mark.parametrize("marker", ["credential", "password", "secret", "signature", "token"])
def test_redacts_query_name_markers_case_insensitively(marker: str) -> None:
    name = f"client-{marker.upper()}-value"
    url = f"https://host/p?{name}=example"
    assert redaction.redact_url_credentials(url) == f"https://host/p?{name}=***REDACTED***"


def test_normalises_query_name_hyphens_and_case() -> None:
    assert redaction.redact_url_credentials("https://host/p?API-KEY=example") == (
        "https://host/p?API-KEY=***REDACTED***"
    )


@pytest.mark.parametrize("value", ["Bearer+example", "bEaReR%20example", "BEARER+example"])
def test_redacts_bearer_values_under_any_name(value: str) -> None:
    assert redaction.redact_url_credentials(f"https://host/p?other={value}") == (
        "https://host/p?other=***REDACTED***"
    )


def test_preserves_path_and_nonsensitive_query_parameters() -> None:
    assert (
        redaction.redact_url_credentials("https://host/a/b?view=full&token=example&count=2")
        == "https://host/a/b?view=full&token=***REDACTED***&count=2"
    )


def test_redacts_fragment() -> None:
    assert redaction.redact_url_credentials("https://host/p?view=full#section") == (
        "https://host/p?view=full#***REDACTED***"
    )


def test_url_without_sensitive_parts_is_byte_identical() -> None:
    url = "HTTPS://host/p%2fpart?view=hello%20world&empty=&view=again"
    assert redaction.redact_url_credentials(url) == url


def test_redacts_multiple_urls_in_prose() -> None:
    message = "from https://user:pw@host/a to https://other/b?token=example now"
    assert redaction.redact_url_credentials(message) == (
        "from https://host/a to https://other/b?token=***REDACTED*** now"
    )


def test_unparseable_bracketed_host_is_hidden() -> None:
    assert redaction.redact_url_credentials("visit http://[::1 now") == ("visit [REDACTED URL] now")


def test_url_without_netloc_is_hidden() -> None:
    assert redaction.redact_url_credentials("visit http:///path now") == (
        "visit [REDACTED URL] now"
    )


def test_installation_is_idempotent(httpx_logger: logging.Logger) -> None:
    redaction.install_httpx_log_redaction()
    redaction.install_httpx_log_redaction()

    assert httpx_logger.filters == [redaction._HTTPX_URL_FILTER]


def test_filter_rewrites_formatted_message_and_clears_args(httpx_logger: logging.Logger) -> None:
    records: list[logging.LogRecord] = []

    class Handler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    httpx_logger.addHandler(Handler())
    redaction.install_httpx_log_redaction()
    record = httpx_logger.makeRecord(
        "httpx", logging.INFO, __file__, 1, "request %s", ("https://user:pw@host/p",), None
    )
    httpx_logger.handle(record)

    assert records == [record]
    assert record.msg == "request https://host/p"
    assert record.args == ()
    assert record.getMessage() == "request https://host/p"


def test_filter_redacts_exception_and_stack_info(httpx_logger: logging.Logger) -> None:
    try:
        raise ValueError("failed https://host/p?token=example")
    except ValueError:
        exc_info = sys.exc_info()

    redaction.install_httpx_log_redaction()
    record = httpx_logger.makeRecord(
        "httpx",
        logging.ERROR,
        __file__,
        1,
        "request failed",
        (),
        exc_info,
        sinfo="stack https://user:pw@host/p",
    )
    assert httpx_logger.filter(record)

    assert record.exc_text is not None
    assert "failed https://host/p?token=***REDACTED***" in record.exc_text
    assert record.stack_info == "stack https://host/p"
    formatted = logging.Formatter().format(record)
    assert "failed https://host/p?token=***REDACTED***" in formatted
    assert "stack https://host/p" in formatted
    assert "token=example" not in formatted
    assert "user:pw" not in formatted


def test_filter_redacts_existing_exception_text(httpx_logger: logging.Logger) -> None:
    redaction.install_httpx_log_redaction()
    record = httpx_logger.makeRecord("httpx", logging.ERROR, __file__, 1, "failed", (), None)
    record.exc_text = "failed https://host/p?key=example"

    assert httpx_logger.filter(record)
    assert record.exc_text == "failed https://host/p?key=***REDACTED***"


def test_filter_fails_closed_if_message_formatting_raises(httpx_logger: logging.Logger) -> None:
    try:
        raise ValueError("https://host/p?token=example")
    except ValueError:
        exc_info = sys.exc_info()

    redaction.install_httpx_log_redaction()
    record = httpx_logger.makeRecord(
        "httpx", logging.ERROR, __file__, 1, "%d", ("https://user:pw@host/p",), exc_info
    )
    record.exc_text = "https://host/p?token=example"
    record.stack_info = "https://host/p?token=example"

    assert httpx_logger.filter(record)
    assert record.msg == "[REDACTED HTTP client log message]"
    assert record.args == ()
    assert record.exc_info is None
    assert record.exc_text is None
    assert record.stack_info is None

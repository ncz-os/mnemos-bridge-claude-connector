from __future__ import annotations

import logging
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_REDACTED = "***REDACTED***"
_URL_PATTERN = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s<>\"']+", re.IGNORECASE)
_SENSITIVE_QUERY_NAMES = {
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "bearer",
    "jwt",
    "key",
    "sig",
}
_SENSITIVE_QUERY_MARKERS = ("credential", "password", "secret", "signature", "token")


def _is_sensitive_query_parameter(name: str, value: str) -> bool:
    normalised_name = name.casefold().replace("-", "_")
    return (
        normalised_name in _SENSITIVE_QUERY_NAMES
        or any(marker in normalised_name for marker in _SENSITIVE_QUERY_MARKERS)
        or value.casefold().startswith("bearer ")
    )


def _redact_url(url: str) -> str:
    """Return a URL safe for logs, or hide it entirely if it cannot be parsed."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return "[REDACTED URL]"

    if not parsed.scheme or not parsed.netloc:
        return "[REDACTED URL]"

    netloc = parsed.netloc.rsplit("@", 1)[-1]
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    redacted_query_items = [
        (name, _REDACTED if _is_sensitive_query_parameter(name, value) else value)
        for name, value in query_items
    ]

    if netloc == parsed.netloc and redacted_query_items == query_items and not parsed.fragment:
        return url

    return urlunsplit(
        (
            parsed.scheme,
            netloc,
            parsed.path,
            urlencode(redacted_query_items, doseq=True, safe="*"),
            _REDACTED if parsed.fragment else "",
        )
    )


def redact_url_credentials(message: str) -> str:
    """Redact credentials from every parsed URL embedded in a message."""
    return _URL_PATTERN.sub(lambda match: _redact_url(match.group(0)), message)


class _CredentialUrlFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
            record.msg = redact_url_credentials(message)
            if record.exc_info:
                exception_text = logging.Formatter().formatException(record.exc_info)
                record.exc_text = redact_url_credentials(exception_text)
            elif record.exc_text:
                record.exc_text = redact_url_credentials(record.exc_text)
            if record.stack_info:
                record.stack_info = redact_url_credentials(record.stack_info)
        except Exception:  # noqa: BLE001 - log filtering must fail closed
            # Log sanitisation must fail closed: formatting bugs cannot expose a URL.
            record.msg = "[REDACTED HTTP client log message]"
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        record.args = ()
        return True


_HTTPX_URL_FILTER = _CredentialUrlFilter()


def install_httpx_log_redaction() -> None:
    httpx_logger = logging.getLogger("httpx")
    if _HTTPX_URL_FILTER not in httpx_logger.filters:
        httpx_logger.addFilter(_HTTPX_URL_FILTER)


__all__ = ["install_httpx_log_redaction", "redact_url_credentials"]

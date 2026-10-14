"""
Phase 10 — Burp Suite collector.

Real caveat worth stating plainly: Burp Suite Community Edition has NO
REST API. Live automated export needs either Burp Suite Professional
(which does have a REST API) or the Logger++ extension exporting to a
JSON/CSV file that this module then parses. This is that parser.

Logger++'s exact export field names have varied across versions, so
_extract_entry() checks a few common key spellings per field rather
than assuming one exact schema — adjust the alias lists below if your
installed version's export differs; run parse_logger_export() against
one real exported file first and diff the fields before trusting it.
"""

from __future__ import annotations

import json

from normalization.event_schema import NexusEvent

_FIELD_ALIASES = {
    "method": ["method", "Method", "http_method"],
    "url": ["url", "URL"],
    "path": ["path", "Path"],
    "status": ["status", "Status", "status_code", "responseStatus"],
    "host": ["host", "Host", "destination_ip", "IP"],
}


def _first(entry: dict, keys: list[str], default=None):
    for k in keys:
        if k in entry:
            return entry[k]
    return default


def parse_logger_export(json_text: str) -> list[NexusEvent]:
    try:
        payload = json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Could not parse Burp Logger++ export as JSON: {exc}") from exc

    entries = payload if isinstance(payload, list) else payload.get("entries", [])
    events = []
    for entry in entries:
        method = _first(entry, _FIELD_ALIASES["method"], "GET")
        path = _first(entry, _FIELD_ALIASES["path"]) or _first(entry, _FIELD_ALIASES["url"], "")
        status = _first(entry, _FIELD_ALIASES["status"])
        host = _first(entry, _FIELD_ALIASES["host"])

        try:
            status_int = int(status) if status is not None else None
        except (TypeError, ValueError):
            status_int = None

        events.append(NexusEvent(
            source="burp",
            event_type="http_request",
            destination_ip=host,
            severity="low",
            confidence=0.7,
            data={"method": method, "path": path, "status": status_int},
        ))
    return events

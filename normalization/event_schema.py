"""
Phase 2 — Unified Event Schema.

Every collector (nmap, scapy, burp, linux, capa, wireshark) is expected
to eventually produce a NexusEvent. This module is the one place that
defines what a valid event looks like and enforces it, so a malformed
event from a sloppy collector can never silently corrupt the database.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional

VALID_SEVERITIES = {"low", "medium", "high", "critical"}

# Deliberately not an enum: new collectors will add new event_types over
# time, and locking this down too early just means editing this file
# every time you add a detector. Severity is more load-bearing (it
# drives risk scoring), so that one IS enforced.
VALID_SOURCES = {
    "nmap", "scapy", "wireshark", "burp", "linux", "capa",
    # Internal sources: events NEXUS itself generates rather than
    # events collected from an external tool.
    "detection", "correlation",
}


class EventValidationError(ValueError):
    """Raised when raw input can't be turned into a valid NexusEvent."""


@dataclass
class NexusEvent:
    source: str
    event_type: str
    severity: str = "low"
    confidence: float = 0.5
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    data: dict[str, Any] = field(default_factory=dict)

    # Generated, not supplied by the caller.
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        if self.source not in VALID_SOURCES:
            raise EventValidationError(
                f"Unknown source '{self.source}'. Expected one of {sorted(VALID_SOURCES)}."
            )
        if not self.event_type:
            raise EventValidationError("event_type is required.")
        if self.severity not in VALID_SEVERITIES:
            raise EventValidationError(
                f"Invalid severity '{self.severity}'. Expected one of {sorted(VALID_SEVERITIES)}."
            )
        if not (0.0 <= self.confidence <= 1.0):
            raise EventValidationError("confidence must be between 0.0 and 1.0.")
        for port_field in ("source_port", "destination_port"):
            port = getattr(self, port_field)
            if port is not None and not (0 <= port <= 65535):
                raise EventValidationError(f"{port_field} out of range: {port}")

    def to_json(self) -> str:
        """Serialize to a single JSON line (no embedded newlines)."""
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "NexusEvent":
        """
        Build a NexusEvent from a raw dict (e.g. decoded from the wire).

        Unknown/extra keys are ignored rather than rejected — collectors
        evolve independently from the schema, and a stricter approach
        would mean every new field breaks every existing collector.
        event_id/timestamp are only honored if present, otherwise generated.
        """
        known_fields = {
            "source", "event_type", "severity", "confidence", "source_ip",
            "destination_ip", "source_port", "destination_port", "protocol",
            "data", "event_id", "timestamp",
        }
        filtered = {k: v for k, v in payload.items() if k in known_fields}
        try:
            return cls(**filtered)
        except TypeError as exc:
            raise EventValidationError(f"Malformed event payload: {exc}") from exc

    @classmethod
    def from_json(cls, raw: str) -> "NexusEvent":
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise EventValidationError(f"Invalid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise EventValidationError("Event JSON must be an object.")
        return cls.from_dict(payload)

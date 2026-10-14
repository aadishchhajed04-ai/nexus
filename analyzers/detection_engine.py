"""
Phase 6 — Detection engine.

Deterministic rule-based detection, run over a sliding time window.
Each rule looks at events grouped by source_ip and, if a threshold is
crossed, emits one new NexusEvent (source="detection") describing the
pattern. These detection events are what the correlation engine later
groups into incidents — raw collector events feed detections, and
detections feed incidents. Nothing here is machine learning, per the
blueprint's own "do not start with ML" guidance.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from analyzers import rules
from database.database import Database
from normalization.event_schema import NexusEvent


def run_detection(db: Database, now: datetime | None = None) -> list[NexusEvent]:
    """
    Scan the last TIME_WINDOW_SECONDS of events for all four rules and
    persist any detection events found. Returns the newly created events
    so the caller (server or correlation pipeline) can act on them
    immediately without a second DB round-trip.
    """
    now = now or datetime.now(timezone.utc)
    since = (now - timedelta(seconds=rules.TIME_WINDOW_SECONDS)).isoformat()
    recent = db.get_events_since(since)

    new_events: list[NexusEvent] = []
    new_events += _detect_port_scan(recent)
    new_events += _detect_connection_burst(recent)
    new_events += _detect_web_anomaly(recent)
    new_events += _detect_auth_failure_burst(recent)

    for event in new_events:
        db.insert_event(event)

    return new_events


def _detect_port_scan(events) -> list[NexusEvent]:
    ports_by_source: dict[str, set[int]] = defaultdict(set)
    dest_by_source: dict[str, str] = {}

    for e in events:
        if e["destination_port"] is not None and e["source_ip"] is not None:
            ports_by_source[e["source_ip"]].add(e["destination_port"])
            dest_by_source[e["source_ip"]] = e["destination_ip"]

    detections = []
    for source_ip, ports in ports_by_source.items():
        if len(ports) >= rules.PORT_SCAN_THRESHOLD:
            detections.append(NexusEvent(
                source="detection", event_type="port_scan",
                source_ip=source_ip, destination_ip=dest_by_source.get(source_ip),
                severity="medium", confidence=0.85,
                data={"distinct_ports": len(ports), "ports": sorted(ports)[:50]},
            ))
    return detections


def _detect_connection_burst(events) -> list[NexusEvent]:
    counts: dict[str, int] = defaultdict(int)
    dest_by_source: dict[str, str] = {}
    for e in events:
        if e["source_ip"] is not None:
            counts[e["source_ip"]] += 1
            if e["destination_ip"]:
                dest_by_source[e["source_ip"]] = e["destination_ip"]

    detections = []
    for source_ip, count in counts.items():
        if count >= rules.CONNECTION_THRESHOLD:
            detections.append(NexusEvent(
                source="detection", event_type="connection_burst",
                source_ip=source_ip, destination_ip=dest_by_source.get(source_ip),
                severity="medium", confidence=0.8,
                data={"connection_count": count},
            ))
    return detections


def _detect_web_anomaly(events) -> list[NexusEvent]:
    detections = []
    for e in events:
        if e["source"] != "burp" or e["event_type"] != "http_request":
            continue
        raw = (e["raw_data"] or "").lower()
        for pattern in rules.SUSPICIOUS_HTTP_PATTERNS:
            if pattern.lower() in raw:
                detections.append(NexusEvent(
                    source="detection", event_type="web_anomaly",
                    source_ip=e["source_ip"], destination_ip=e["destination_ip"],
                    severity="high", confidence=0.75,
                    data={"matched_pattern": pattern, "triggering_event_id": e["event_id"]},
                ))
                break
    return detections


def _detect_auth_failure_burst(events) -> list[NexusEvent]:
    counts: dict[str, int] = defaultdict(int)
    dest_by_source: dict[str, str] = {}
    for e in events:
        if e["source"] == "linux" and e["event_type"] == "login_failure" and e["source_ip"]:
            counts[e["source_ip"]] += 1
            if e["destination_ip"]:
                dest_by_source[e["source_ip"]] = e["destination_ip"]

    detections = []
    for source_ip, count in counts.items():
        if count >= rules.AUTH_FAILURE_THRESHOLD:
            detections.append(NexusEvent(
                source="detection", event_type="auth_failure_burst",
                source_ip=source_ip, destination_ip=dest_by_source.get(source_ip),
                severity="high", confidence=0.85,
                data={"failure_count": count},
            ))
    return detections

"""
Phase 8 — Risk engine.

Deliberately simple and explainable: a capped sum of fixed weights per
distinct contributing factor found among an incident's linked events.
This is an internal prioritization score, not a calibrated probability
— the blueprint says this explicitly, and the dashboard (Phase 9) must
show the breakdown, never just the number, so an analyst can see why.

Each factor counts once per incident even if the underlying event
repeats (e.g. two port-scan detections don't double the score) — the
score answers "how many different bad things are going on here", not
"how many times did one bad thing happen".
"""

from __future__ import annotations

import json

from analyzers import rules
from database.database import Database

MAX_SCORE = 100


def _severity_for_score(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def compute_risk(db: Database, incident_id: int) -> tuple[int, str, list[tuple[str, int]]]:
    events = db.get_incident_events(incident_id)
    breakdown: list[tuple[str, int]] = []
    seen: set[str] = set()

    def add(factor_key: str, label: str, weight: int) -> None:
        if factor_key not in seen:
            breakdown.append((label, weight))
            seen.add(factor_key)

    for e in events:
        et = e["event_type"]

        if et == "port_scan":
            add("port_scan", "Port scan", 20)

        elif et == "service_discovery" and e["destination_port"] in rules.SENSITIVE_PORTS:
            add("sensitive_service", "Sensitive service exposed", 15)

        elif et == "connection_burst":
            add("connection_burst", "Repeated/burst connections", 15)

        elif et == "web_anomaly":
            add("web_anomaly", "Suspicious web activity", 20)

        elif et == "auth_failure_burst":
            add("auth_failure_burst", "Repeated authentication failures", 15)

        elif et == "file_analysis":
            try:
                data = json.loads(e["raw_data"] or "{}").get("data", {})
            except json.JSONDecodeError:
                data = {}
            if data.get("capabilities"):
                add("suspicious_file", "Suspicious file capability", 15)

    score = min(MAX_SCORE, sum(weight for _, weight in breakdown))
    severity = _severity_for_score(score)
    db.update_incident_risk(incident_id, score, severity)
    return score, severity, breakdown

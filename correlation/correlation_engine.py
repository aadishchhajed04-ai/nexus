"""
Phase 7 — Correlation engine.

Runs after detection. For each new detection event, finds an existing
OPEN incident touching the same IP (so a follow-up detection joins the
same investigation instead of spawning a duplicate), or creates one.
Then pulls in the raw collector events from the same time window that
share that IP — this is what turns "five unrelated alerts" into "one
incident with five pieces of evidence," which is the whole point of
NEXUS per the blueprint.

Correlation key used here is IP + time window, matching the blueprint's
"start with" list. Deliberately not using hostname/user/session yet —
those need the host agent (Phase 11) wired in first, and a correlation
key that's silently always-empty is worse than one that's simple but
actually populated.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from analyzers import rules
from database.database import Database
from normalization.event_schema import NexusEvent

_TITLES = {
    "port_scan": "Possible Network Reconnaissance",
    "connection_burst": "Unusual Connection Volume",
    "web_anomaly": "Suspicious Web Activity",
    "auth_failure_burst": "Repeated Authentication Failures",
}


def correlate(db: Database, detection_events: list[NexusEvent], now: datetime | None = None) -> list[int]:
    now = now or datetime.now(timezone.utc)
    since = (now - timedelta(seconds=rules.TIME_WINDOW_SECONDS)).isoformat()
    touched_incident_ids: list[int] = []

    for det in detection_events:
        ip = det.source_ip or det.destination_ip
        if not ip:
            continue

        existing = db.find_incident_for_ip(
            ip, since_iso=(now - timedelta(seconds=rules.CORRELATION_TTL_SECONDS)).isoformat()
        )
        if existing:
            incident_id = existing["incident_id"]
        else:
            title = f"{_TITLES.get(det.event_type, 'Security Event')} — {ip}"
            incident_id = db.create_incident(
                title=title,
                description=f"Auto-created from a '{det.event_type}' detection involving {ip}.",
                risk_score=0,
                severity="low",
            )

        db.link_event_to_incident(incident_id, det.event_id)

        # Pull in supporting raw events sharing this IP within the window.
        for e in db.get_events_since(since):
            if e["source_ip"] == ip or e["destination_ip"] == ip:
                db.link_event_to_incident(incident_id, e["event_id"])

        touched_incident_ids.append(incident_id)

    return list(dict.fromkeys(touched_incident_ids))  # de-duped, order preserved

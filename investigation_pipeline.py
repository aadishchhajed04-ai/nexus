"""
The glue the blueprint's architecture diagram implies but never actually
specifies: what runs, in what order, when a new event lands. This is
that answer, in one place, so it's not scattered across the server and
API modules.
"""

from __future__ import annotations

import logging

from analyzers.detection_engine import run_detection
from correlation.correlation_engine import correlate
from database.database import Database
from risk.risk_engine import compute_risk

log = logging.getLogger("nexus.pipeline")


def process_pipeline(db: Database) -> list[dict]:
    """
    Run detection over the current time window, correlate any new
    detections into incidents, and recompute risk for every incident
    touched. Returns a list of {incident_id, score, severity, breakdown,
    title} dicts for whatever the caller wants to do next (broadcast
    over WebSocket, log, etc.) — this function has no opinion on that.
    """
    detections = run_detection(db)
    if not detections:
        return []

    incident_ids = correlate(db, detections)
    results = []
    for incident_id in incident_ids:
        score, severity, breakdown = compute_risk(db, incident_id)
        incident = db.get_incident(incident_id)
        results.append({
            "incident_id": incident_id,
            "title": incident["title"],
            "risk_score": score,
            "severity": severity,
            "breakdown": breakdown,
        })
        log.info(f"Incident #{incident_id} updated: risk={score} severity={severity}")
    return results

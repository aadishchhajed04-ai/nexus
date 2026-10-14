"""
Phase 14 — MITRE ATT&CK mapping.

Static lookup from a detection event_type to a technique — deliberately
NOT automatic/fuzzy matching. The blueprint is explicit that weak
evidence should not get a technique slapped on it, so this only maps
the handful of event_types the detection engine actually produces with
enough confidence to justify a technique reference in a report.
"""

from __future__ import annotations

ATTACK_MAPPING: dict[str, dict[str, str]] = {
    "port_scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
    },
    "connection_burst": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
    },
    "web_anomaly": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
    },
    "auth_failure_burst": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
    },
    "file_analysis": {
        "technique_id": "T1204",
        "technique_name": "User Execution",
    },
}


def map_technique(event_type: str) -> dict[str, str] | None:
    """Returns {"technique_id", "technique_name"} or None if this
    event_type has no confident mapping — callers must handle None
    rather than assume every event maps to something."""
    return ATTACK_MAPPING.get(event_type)

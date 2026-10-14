"""
Phase 3 — Database access layer.

Thin wrapper around sqlite3. Deliberately no ORM: the schema is small
and stable enough that raw SQL is easier to reason about and to show
in a portfolio/demo context than an ORM abstraction layer would be.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from normalization.event_schema import NexusEvent

SCHEMA_PATH = Path(__file__).parent / "schema.sql"
DEFAULT_DB_PATH = Path(__file__).parent / "nexus.db"

# sqlite3 connections aren't safe to share across threads by default,
# and the socket server will handle each agent connection on its own
# thread (see server/socket_server.py). check_same_thread=False plus a
# module-level lock keeps this simple without pulling in a connection
# pool for what is, for now, a single-writer workload.
_write_lock = threading.Lock()


class Database:
    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with open(SCHEMA_PATH, "r") as f:
            self._conn.executescript(f.read())
        self._conn.commit()

    def insert_event(self, event: NexusEvent) -> None:
        with _write_lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO events (
                    event_id, timestamp, source, event_type,
                    source_ip, destination_ip, source_port, destination_port,
                    protocol, severity, confidence, raw_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id, event.timestamp, event.source, event.event_type,
                    event.source_ip, event.destination_ip,
                    event.source_port, event.destination_port,
                    event.protocol, event.severity, event.confidence,
                    event.to_json(),
                ),
            )
            self._conn.commit()

    def get_events(self, limit: int = 100) -> list[sqlite3.Row]:
        cur = self._conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        return cur.fetchall()

    def get_events_since(self, since_iso: str) -> list[sqlite3.Row]:
        """All events with timestamp >= since_iso, oldest first — the
        shape both the detection and correlation engines need."""
        cur = self._conn.execute(
            "SELECT * FROM events WHERE timestamp >= ? ORDER BY timestamp ASC",
            (since_iso,),
        )
        return cur.fetchall()

    def get_event_by_id(self, event_id: str) -> Optional[sqlite3.Row]:
        cur = self._conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,))
        return cur.fetchone()

    def create_incident(self, title: str, description: str, risk_score: int, severity: str) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with _write_lock:
            cur = self._conn.execute(
                """INSERT INTO incidents (created_at, updated_at, title, description, risk_score, severity, status)
                   VALUES (?, ?, ?, ?, ?, ?, 'OPEN')""",
                (now, now, title, description, risk_score, severity),
            )
            self._conn.commit()
            return cur.lastrowid

    def link_event_to_incident(self, incident_id: int, event_id: str) -> None:
        with _write_lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES (?, ?)",
                (incident_id, event_id),
            )
            self._conn.commit()

    def update_incident_risk(self, incident_id: int, risk_score: int, severity: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with _write_lock:
            self._conn.execute(
                "UPDATE incidents SET risk_score = ?, severity = ?, updated_at = ? WHERE incident_id = ?",
                (risk_score, severity, now, incident_id),
            )
            self._conn.commit()

    def update_incident_status(self, incident_id: int, status: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with _write_lock:
            self._conn.execute(
                "UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?",
                (status, now, incident_id),
            )
            self._conn.commit()

    def get_incident(self, incident_id: int) -> Optional[sqlite3.Row]:
        cur = self._conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
        return cur.fetchone()

    def get_incidents(self, limit: int = 100) -> list[sqlite3.Row]:
        cur = self._conn.execute(
            "SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?", (limit,)
        )
        return cur.fetchall()

    def get_incident_events(self, incident_id: int) -> list[sqlite3.Row]:
        cur = self._conn.execute(
            """SELECT e.* FROM events e
               JOIN incident_events ie ON e.event_id = ie.event_id
               WHERE ie.incident_id = ?
               ORDER BY e.timestamp ASC""",
            (incident_id,),
        )
        return cur.fetchall()

    def find_incident_for_ip(self, ip: str, since_iso: str) -> Optional[sqlite3.Row]:
        """Most recent OPEN incident touching this IP that's been active
        since `since_iso`, if any — lets the correlation engine add to an
        existing incident instead of always creating a new one, while an
        incident nobody has touched in a while ages out and stops
        silently absorbing unrelated new activity on the same IP."""
        cur = self._conn.execute(
            """SELECT i.* FROM incidents i
               JOIN incident_events ie ON i.incident_id = ie.incident_id
               JOIN events e ON e.event_id = ie.event_id
               WHERE (e.source_ip = ? OR e.destination_ip = ?)
                 AND i.status = 'OPEN' AND i.updated_at >= ?
               ORDER BY i.updated_at DESC LIMIT 1""",
            (ip, ip, since_iso),
        )
        return cur.fetchone()

    def get_event_count(self) -> int:
        cur = self._conn.execute("SELECT COUNT(*) AS n FROM events")
        return cur.fetchone()["n"]

    def close(self) -> None:
        self._conn.close()

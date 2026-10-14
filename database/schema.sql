-- Phase 3 — Database schema.
-- Indexes added beyond the blueprint's bare column list: correlation and
-- dashboard filtering both query by IP and by time constantly, and an
-- events table with no indexes on those columns will get slow fast once
-- you're running the multi-source demo scenarios.

CREATE TABLE IF NOT EXISTS events (
    event_id         TEXT PRIMARY KEY,
    timestamp        TEXT NOT NULL,
    source            TEXT NOT NULL,
    event_type        TEXT NOT NULL,
    source_ip         TEXT,
    destination_ip    TEXT,
    source_port       INTEGER,
    destination_port  INTEGER,
    protocol          TEXT,
    severity          TEXT NOT NULL,
    confidence        REAL NOT NULL,
    raw_data          TEXT  -- full original JSON, for the report generator later
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events (source_ip);
CREATE INDEX IF NOT EXISTS idx_events_destination_ip ON events (destination_ip);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events (event_type);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    title         TEXT NOT NULL,
    description   TEXT,
    risk_score    INTEGER NOT NULL DEFAULT 0,
    severity      TEXT NOT NULL DEFAULT 'low',
    status        TEXT NOT NULL DEFAULT 'OPEN'
);

CREATE TABLE IF NOT EXISTS incident_events (
    incident_id  INTEGER NOT NULL REFERENCES incidents (incident_id),
    event_id     TEXT NOT NULL REFERENCES events (event_id),
    PRIMARY KEY (incident_id, event_id)
);

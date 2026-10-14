"""
The "server" the frontend actually talks to.

Design decision (diverges from the blueprint, documented in README):
the socket backbone, REST API, and WebSocket broadcaster all run in
ONE process here, not three separately-deployed services. The
blueprint's architecture diagram draws them as separate boxes but
never specifies how they'd coordinate across process boundaries —
sharing one asyncio event loop is what actually makes "new TCP event
-> pipeline -> live WebSocket push" work without a message queue,
which is explicitly an "optional advanced" feature, not core scope.

Auth: a minimal shared-secret bearer token, not full OAuth/user
accounts. That's a deliberate scope call for a portfolio project
running on localhost — swap this for real auth before this touches
any network you don't fully control.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends, Header
from fastapi.middleware.cors import CORSMiddleware

from database.database import Database
from investigation_pipeline import process_pipeline
from normalization.event_schema import EventValidationError, NexusEvent
from server.socket_server import NexusServer

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("nexus.api")

API_TOKEN = os.environ.get("NEXUS_API_TOKEN", "dev-token-change-me")

app = FastAPI(title="NEXUS API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

db = Database()


def require_auth(authorization: str | None = Header(default=None)) -> None:
    expected = f"Bearer {API_TOKEN}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="Missing or invalid bearer token.")


# --- WebSocket connection manager -------------------------------------

class ConnectionManager:
    def __init__(self) -> None:
        self.active: list[WebSocket] = []
        self.loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict) -> None:
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    def broadcast_threadsafe(self, message: dict) -> None:
        """Called from the socket server's own thread — schedules the
        actual send onto the FastAPI event loop instead of touching
        asyncio objects from a non-asyncio thread directly."""
        if self.loop is not None:
            asyncio.run_coroutine_threadsafe(self.broadcast(message), self.loop)


manager = ConnectionManager()


# --- Socket backbone runs in a background thread, in-process ----------

def _on_new_event(event: NexusEvent) -> None:
    manager.broadcast_threadsafe({"type": "event", "event": json.loads(event.to_json())})
    results = process_pipeline(db)
    for r in results:
        manager.broadcast_threadsafe({"type": "incident_update", **_jsonable(r)})


def _jsonable(result: dict) -> dict:
    return {**result, "breakdown": [{"label": l, "weight": w} for l, w in result["breakdown"]]}


_socket_server = NexusServer(db=db, on_event=_on_new_event)


@app.on_event("startup")
def _startup() -> None:
    if API_TOKEN == "dev-token-change-me":
        log.warning(
            "NEXUS_API_TOKEN is unset — using the default demo credential. "
            "Fine for a local demo, do not use this default anywhere else."
        )
    manager.loop = asyncio.get_event_loop()
    thread = threading.Thread(target=_socket_server.start, daemon=True)
    thread.start()
    log.info("NEXUS socket backbone started in background thread.")


@app.on_event("shutdown")
def _shutdown() -> None:
    _socket_server.stop()


# --- REST endpoints -----------------------------------------------------

@app.get("/events")
def get_events(limit: int = 100, _: None = Depends(require_auth)):
    return [dict(row) for row in db.get_events(limit=limit)]


@app.get("/incidents")
def get_incidents(limit: int = 100, _: None = Depends(require_auth)):
    return [dict(row) for row in db.get_incidents(limit=limit)]


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int, _: None = Depends(require_auth)):
    incident = db.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return dict(incident)


@app.get("/timeline/{incident_id}")
def get_timeline(incident_id: int, _: None = Depends(require_auth)):
    incident = db.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return [dict(row) for row in db.get_incident_events(incident_id)]


@app.get("/incidents/{incident_id}/risk")
def get_incident_risk(incident_id: int, _: None = Depends(require_auth)):
    from risk.risk_engine import compute_risk
    incident = db.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    score, severity, breakdown = compute_risk(db, incident_id)
    return {
        "score": score,
        "severity": severity,
        "breakdown": [{"label": label, "weight": weight} for label, weight in breakdown],
    }


@app.post("/incidents/{incident_id}/status")
def set_incident_status(incident_id: int, status: str, _: None = Depends(require_auth)):
    valid = {"OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}
    if status not in valid:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(valid)}")
    incident = db.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    db.update_incident_status(incident_id, status)
    return {"incident_id": incident_id, "status": status}


@app.get("/hosts")
def get_hosts(_: None = Depends(require_auth)):
    cur = db._conn.execute(
        """SELECT destination_ip AS ip, COUNT(*) AS event_count, MAX(timestamp) AS last_seen
           FROM events WHERE destination_ip IS NOT NULL
           GROUP BY destination_ip ORDER BY last_seen DESC"""
    )
    return [dict(row) for row in cur.fetchall()]


@app.get("/services")
def get_services(_: None = Depends(require_auth)):
    cur = db._conn.execute(
        """SELECT destination_ip AS ip, destination_port AS port, protocol,
                  COUNT(*) AS event_count
           FROM events WHERE destination_port IS NOT NULL
           GROUP BY destination_ip, destination_port, protocol
           ORDER BY event_count DESC"""
    )
    return [dict(row) for row in cur.fetchall()]


@app.get("/statistics")
def get_statistics(_: None = Depends(require_auth)):
    total_events = db.get_event_count()
    incidents = db.get_incidents(limit=1000)
    return {
        "total_events": total_events,
        "active_incidents": sum(1 for i in incidents if i["status"] == "OPEN"),
        "critical_incidents": sum(1 for i in incidents if i["severity"] == "critical"),
        "total_incidents": len(incidents),
    }


@app.get("/reports/{incident_id}")
def get_report(incident_id: int, _: None = Depends(require_auth)):
    from reports.report_generator import generate_markdown_report
    try:
        return {"markdown": generate_markdown_report(db, incident_id)}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()  # keep-alive; client doesn't need to send anything meaningful
    except WebSocketDisconnect:
        manager.disconnect(ws)

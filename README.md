# NEXUS — Unified Network Security Investigation Platform

Built in layers, each one tested before the next started — same
philosophy the blueprint itself argues for.

## Status

| Phase | What | Status |
|---|---|---|
| 0 | Environment / repo skeleton | Done |
| 1 | Socket backbone (agent <-> server, NDJSON framing) | Done, tested |
| 2 | Unified event schema + validation | Done, tested |
| 3 | SQLite database (events / incidents / incident_events) | Done, tested |
| 4 | Nmap collector | Done, tested (real scan against localhost) |
| 5 | Scapy packet collector (live + offline pcap) | Done, tested (synthetic pcap) |
| 6 | Detection engine (port scan, connection burst, web anomaly, auth burst) | Done, tested |
| 7 | Correlation engine | Done, tested |
| 8 | Risk engine | Done, tested |
| 9 | Dashboard — React/TS/Tailwind/Recharts/React Flow | Done, builds clean, wired to live WebSocket |
| 10 | Burp Suite collector (Logger++ export parser) | Written, **not live-tested** — see caveat below |
| 11 | Linux host agent (psutil) | Done |
| 12 | CAPA collector | Written, **not live-tested** — see caveat below |
| 13 | Wireshark | Not a live integration — see caveat below |
| 14 | MITRE ATT&CK mapping | Done (static, confidence-gated) |
| 17 | Report generation (Markdown + PDF) | Done |
| — | REST API + WebSocket, auth, Docker | Done |

Everything marked "Done, tested" was actually run in this build --
including a real `nmap` scan and a genuine end-to-end pass of
agent -> socket server -> detection -> correlation -> risk -> REST API
-> WebSocket -> (verified messages arriving). 17+ automated tests pass.

## Caveats, stated plainly

- **Burp Suite Community Edition has no REST API.** The collector
  parses a Logger++ JSON export instead. Logger++'s field names vary
  by version -- run it against one real export and check
  `collectors/burp_collector.py`'s `_FIELD_ALIASES` before trusting it.
- **CAPA** needs its rules repository and a real sample to analyze --
  neither belongs in an automated build. The parser is written against
  capa's documented `-j` output but is untested against a live binary.
- **Cisco Packet Tracer is intentionally not integrated** — it can't
  emit real packet data into the pipeline (the blueprint says so
  itself). It's demo/topology material, not a data source.
- **Wireshark's role here is inspection, not collection** — use it to
  produce/verify a `.pcap`, then feed that file through
  `collectors/scapy_collector.parse_pcap_file()`.
- The socket backbone, REST API, and WebSocket broadcaster run in
  **one process**, not three separately deployed services — the
  blueprint's architecture diagram never specifies how those would
  actually coordinate across process boundaries, and one process
  sharing one event loop is what makes "new event -> live dashboard
  update" work without adding a message queue.

## Fixes from the second pass

These were found and fixed after the first build — logged here rather
than silently folded in, since this is now a graded deliverable:

- **Incident status was unreachable from the UI.** Added a status
  control (`OPEN`/`INVESTIGATING`/`RESOLVED`/`FALSE_POSITIVE`) on the
  incident page, wired to the existing `POST /incidents/{id}/status`
  endpoint.
- **That endpoint was sloppy.** It called `update_incident_risk()` as
  a pointless no-op and bypassed the DB class's write lock by reaching
  into `db._conn` directly. Replaced with a proper
  `Database.update_incident_status()` method.
- **Incidents never aged out.** `find_incident_for_ip` now only
  reuses an OPEN incident if it's been touched within
  `CORRELATION_TTL_SECONDS` (default 300s) — an incident nobody
  resolved eventually stops silently absorbing new, unrelated activity
  on the same IP. Covered by two new tests (staleness + resolved
  incidents aren't reused).
- **Startup now warns** if `NEXUS_API_TOKEN` is left at its default,
  instead of silently shipping a hardcoded credential.
- **Added a frontend smoke-test suite** (`npm test`, vitest +
  React Testing Library + jsdom) that renders every real page through
  the real router with mocked API responses and asserts nothing
  throws — including the React Flow graph and the markdown report
  renderer. This is not the same as a real-browser check (no
  Chromium available in this build environment — Playwright's browser
  CDN isn't reachable from here), but it catches the class of
  render-time bug that `tsc` alone can't.

## Running it

### Option A: Docker Compose

```bash
docker compose up --build
```
Backend on :8000 (REST/WS) and :9090 (TCP socket backbone).
Frontend on :5173.

### Option B: manual, two terminals

```bash
# Terminal 1 — backend (REST + WebSocket + socket backbone, all in one process)
python -m uvicorn api.main:app --reload

# Terminal 2 — frontend
cd frontend
npm install
npm run dev
```
Open http://localhost:5173.

### Sending it a demo event

```bash
python -m agents.socket_agent
```
Or run an authorized nmap scan through the real collector:
```python
from collectors.nmap_collector import run_nmap_scan
from agents.socket_agent import NexusAgent

events = run_nmap_scan("127.0.0.1", ports="1-1000")
with NexusAgent() as agent:
    for e in events:
        agent.send_event(e)
```

## Tests

```bash
# backend (12 tests)
python -m unittest discover -s tests -v

# frontend (5 smoke tests — every page, mocked API, jsdom)
cd frontend && npm test
```

## Auth

REST calls need `Authorization: Bearer <NEXUS_API_TOKEN>`
(default `dev-token-change-me`, set via env var). This is a
shared-secret token for a localhost portfolio project, not real
multi-user auth — replace it before this runs anywhere else.

"""
Phase 1 — Socket backbone (agent side).

Base agent that any collector (nmap, scapy, etc.) can build on: connect
to the server, send NexusEvent objects as newline-delimited JSON, and
keep the connection open for as many events as the caller wants to send.
"""

from __future__ import annotations

import socket

from normalization.event_schema import NexusEvent
from server.config import HOST, MESSAGE_DELIMITER, PORT


class NexusAgent:
    def __init__(self, host: str = HOST, port: int = PORT):
        self.host = host
        self.port = port
        self._sock: socket.socket | None = None

    def connect(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((self.host, self.port))

    def send_event(self, event: NexusEvent) -> None:
        if self._sock is None:
            raise RuntimeError("Agent is not connected. Call connect() first.")
        payload = event.to_json().encode("utf-8") + MESSAGE_DELIMITER
        self._sock.sendall(payload)

    def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None

    def __enter__(self) -> "NexusAgent":
        self.connect()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


if __name__ == "__main__":
    # Manual smoke test / first-milestone demo:
    #   python -m agents.socket_agent
    demo_event = NexusEvent(
        source="nmap",
        event_type="service_discovery",
        destination_ip="10.0.0.20",
        destination_port=22,
        protocol="tcp",
        severity="low",
        confidence=0.9,
        data={"service": "ssh", "version": "OpenSSH 8.9"},
    )
    with NexusAgent() as agent:
        print("[AGENT] Sending event...")
        agent.send_event(demo_event)
        print(f"[AGENT] Sent: {demo_event.event_type}")

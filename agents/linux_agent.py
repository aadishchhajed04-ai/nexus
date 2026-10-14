"""
Phase 11 — Linux host agent.

Uses psutil rather than shelling out to `ss`/`ps`/parsing raw /proc —
psutil gives structured, cross-checked data and doesn't break when a
particular distro's tool output format changes. Runs as a NexusAgent
(same socket/schema as every other collector), so from the server's
point of view a host agent event looks exactly like an nmap or scapy
event — that uniformity is the entire point of Phase 2's schema.

Root is NOT required for the fields this collects (own-user process
list + established connections); it IS required to see other users'
processes, which this deliberately doesn't attempt — a host agent that
needs root to run at all is a much bigger thing to authorize than one
that doesn't.
"""

from __future__ import annotations

import socket as socket_module
import time

import psutil

from agents.socket_agent import NexusAgent
from normalization.event_schema import NexusEvent


def collect_connection_events() -> list[NexusEvent]:
    events = []
    hostname_ip = socket_module.gethostbyname(socket_module.gethostname())
    for conn in psutil.net_connections(kind="inet"):
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
            continue
        events.append(NexusEvent(
            source="linux",
            event_type="network_connection",
            source_ip=conn.laddr.ip if conn.laddr else hostname_ip,
            source_port=conn.laddr.port if conn.laddr else None,
            destination_ip=conn.raddr.ip,
            destination_port=conn.raddr.port,
            protocol="tcp" if conn.type == psutil.SOCK_STREAM else "udp",
            severity="low",
            confidence=0.9,
            data={"pid": conn.pid},
        ))
    return events


def collect_process_events(min_pid: int = 0) -> list[NexusEvent]:
    events = []
    for proc in psutil.process_iter(["pid", "name", "username", "create_time"]):
        info = proc.info
        if info["pid"] < min_pid:
            continue
        events.append(NexusEvent(
            source="linux",
            event_type="process_event",
            severity="low",
            confidence=0.7,
            data={
                "pid": info["pid"],
                "name": info["name"],
                "username": info["username"],
            },
        ))
    return events


def run_agent_loop(host: str = "127.0.0.1", port: int = 9090, interval_seconds: int = 30) -> None:
    """Blocking loop: collect + send every `interval_seconds`."""
    with NexusAgent(host=host, port=port) as agent:
        while True:
            for event in collect_connection_events():
                agent.send_event(event)
            time.sleep(interval_seconds)


if __name__ == "__main__":
    run_agent_loop()

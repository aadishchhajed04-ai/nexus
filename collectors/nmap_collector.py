"""
Phase 4 — Nmap collector.

Two entry points, kept separate on purpose:
  - run_nmap_scan(): actually invokes the nmap binary (needs it installed
    and needs authorization to scan the target).
  - parse_nmap_xml(): pure parsing, takes XML text in, returns events out.

Splitting them means the parser can be unit-tested with a fixed XML
fixture without needing nmap installed, root privileges, or a live
target — and it's the parser, not the subprocess call, that's actually
at risk of breaking when nmap changes its output format.
"""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone

from normalization.event_schema import NexusEvent


class NmapCollectorError(RuntimeError):
    pass


def run_nmap_scan(target: str, ports: str = "1-1000", extra_args: list[str] | None = None) -> list[NexusEvent]:
    """
    Run nmap against `target` and return NexusEvents.

    Only scan hosts/networks you are authorized to scan. This function
    does not enforce that — it's on the caller, same as the blueprint's
    own repeated "authorized lab only" notes.
    """
    cmd = ["nmap", "-oX", "-", "-p", ports] + (extra_args or []) + [target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=True)
    except FileNotFoundError as exc:
        raise NmapCollectorError("nmap binary not found on PATH.") from exc
    except subprocess.CalledProcessError as exc:
        raise NmapCollectorError(f"nmap exited with error: {exc.stderr}") from exc
    except subprocess.TimeoutExpired as exc:
        raise NmapCollectorError("nmap scan timed out.") from exc

    return parse_nmap_xml(result.stdout)


def parse_nmap_xml(xml_text: str) -> list[NexusEvent]:
    """Parse `nmap -oX` output into host_discovered / service_discovery events."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapCollectorError(f"Could not parse nmap XML: {exc}") from exc

    events: list[NexusEvent] = []

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue

        addr_el = host_el.find("address")
        if addr_el is None:
            continue
        host_ip = addr_el.get("addr")

        events.append(
            NexusEvent(
                source="nmap",
                event_type="host_discovered",
                destination_ip=host_ip,
                severity="low",
                confidence=0.95,
                data={"status": "up"},
            )
        )

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            port_id = int(port_el.get("portid"))
            protocol = port_el.get("protocol", "tcp")
            service_el = port_el.find("service")
            service_name = service_el.get("name") if service_el is not None else "unknown"
            service_product = service_el.get("product") if service_el is not None else None
            service_version = service_el.get("version") if service_el is not None else None

            events.append(
                NexusEvent(
                    source="nmap",
                    event_type="service_discovery",
                    destination_ip=host_ip,
                    destination_port=port_id,
                    protocol=protocol,
                    severity="low",
                    confidence=0.9,
                    data={
                        "service": service_name,
                        "product": service_product,
                        "version": service_version,
                    },
                )
            )

    return events


def load_fixture(path: str) -> list[NexusEvent]:
    """Convenience for tests/demos: parse a saved nmap XML file."""
    with open(path, "r") as f:
        return parse_nmap_xml(f.read())

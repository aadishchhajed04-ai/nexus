"""
Phase 5 — Scapy packet collector.

Two entry points:
  - sniff_live(): captures real traffic. Needs root/CAP_NET_RAW and a
    real interface — will not work in most sandboxed/CI environments,
    and that's expected, not a bug.
  - parse_pcap_file(): reads packets from a .pcap/.pcapng file. This is
    what's actually testable without root, and it's also what Phase 13
    (Wireshark workflow) reuses — Wireshark's job is to produce/inspect
    the pcap, not to be integrated with directly.
"""

from __future__ import annotations

from typing import Optional

from scapy.all import IP, TCP, UDP, ICMP, sniff, rdpcap
from scapy.packet import Packet

from normalization.event_schema import NexusEvent


def _packet_to_event(pkt: Packet) -> Optional[NexusEvent]:
    if IP not in pkt:
        return None

    ip_layer = pkt[IP]
    base = {
        "source": "scapy",
        "source_ip": ip_layer.src,
        "destination_ip": ip_layer.dst,
        "severity": "low",
        "confidence": 0.6,
    }

    if TCP in pkt:
        tcp = pkt[TCP]
        flags = str(tcp.flags)
        return NexusEvent(
            event_type="packet_observed",
            protocol="tcp",
            source_port=int(tcp.sport),
            destination_port=int(tcp.dport),
            data={"flags": flags, "size": len(pkt)},
            **base,
        )
    if UDP in pkt:
        udp = pkt[UDP]
        return NexusEvent(
            event_type="packet_observed",
            protocol="udp",
            source_port=int(udp.sport),
            destination_port=int(udp.dport),
            data={"size": len(pkt)},
            **base,
        )
    if ICMP in pkt:
        return NexusEvent(
            event_type="packet_observed",
            protocol="icmp",
            data={"icmp_type": int(pkt[ICMP].type), "size": len(pkt)},
            **base,
        )
    return None


def parse_pcap_file(path: str) -> list[NexusEvent]:
    packets = rdpcap(path)
    events = []
    for pkt in packets:
        event = _packet_to_event(pkt)
        if event is not None:
            events.append(event)
    return events


def sniff_live(interface: str, count: int = 100, timeout: int = 30) -> list[NexusEvent]:
    """
    Requires root/CAP_NET_RAW. Raises PermissionError with a clear
    message rather than a cryptic scapy traceback if not privileged.
    """
    try:
        packets = sniff(iface=interface, count=count, timeout=timeout)
    except PermissionError:
        raise PermissionError(
            "Live packet capture needs root or CAP_NET_RAW "
            "(e.g. run with sudo, or: setcap cap_net_raw+eip $(which python3))"
        )
    events = []
    for pkt in packets:
        event = _packet_to_event(pkt)
        if event is not None:
            events.append(event)
    return events

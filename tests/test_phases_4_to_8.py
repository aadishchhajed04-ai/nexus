import subprocess
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from analyzers.detection_engine import run_detection
from collectors.nmap_collector import parse_nmap_xml, run_nmap_scan, NmapCollectorError
from collectors.scapy_collector import parse_pcap_file
from correlation.correlation_engine import correlate
from database.database import Database
from normalization.event_schema import NexusEvent
from risk.risk_engine import compute_risk

TEST_DB = Path(__file__).parent / "test_phases_4_8.db"


class TestNmapCollector(unittest.TestCase):
    def test_parse_fixture_xml(self):
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host><status state="up"/>
            <address addr="10.0.0.20" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh" product="OpenSSH" version="8.9"/>
              </port>
              <port protocol="tcp" portid="80">
                <state state="closed"/>
                <service name="http"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        events = parse_nmap_xml(xml)
        types = [e.event_type for e in events]
        self.assertIn("host_discovered", types)
        self.assertEqual(types.count("service_discovery"), 1)  # port 80 was closed, filtered out
        service_event = [e for e in events if e.event_type == "service_discovery"][0]
        self.assertEqual(service_event.destination_port, 22)
        self.assertEqual(service_event.data["service"], "ssh")

    def test_live_scan_against_localhost(self):
        try:
            events = run_nmap_scan("127.0.0.1", ports="22,80,443")
        except NmapCollectorError as exc:
            self.skipTest(f"nmap not usable in this environment: {exc}")
        self.assertTrue(any(e.event_type == "host_discovered" for e in events))

    def test_malformed_xml_raises(self):
        with self.assertRaises(NmapCollectorError):
            parse_nmap_xml("not xml at all")


class TestScapyCollector(unittest.TestCase):
    def test_parse_synthetic_pcap(self):
        from scapy.all import IP, TCP, wrpcap
        pkts = [
            IP(src="10.0.0.5", dst="10.0.0.20") / TCP(sport=5000, dport=22, flags="S"),
            IP(src="10.0.0.5", dst="10.0.0.20") / TCP(sport=5000, dport=80, flags="S"),
        ]
        pcap_path = "/tmp/nexus_test.pcap"
        wrpcap(pcap_path, pkts)

        events = parse_pcap_file(pcap_path)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].source, "scapy")
        self.assertEqual(events[0].destination_port, 22)


class TestDetectionCorrelationRisk(unittest.TestCase):
    def setUp(self):
        TEST_DB.unlink(missing_ok=True)
        self.db = Database(db_path=TEST_DB)

    def tearDown(self):
        self.db.close()
        TEST_DB.unlink(missing_ok=True)

    def test_port_scan_detected_correlated_and_scored(self):
        # Simulate an nmap sweep: one source_ip hitting 12 distinct ports
        # on one destination — above PORT_SCAN_THRESHOLD (10).
        for port in range(20, 32):
            self.db.insert_event(NexusEvent(
                source="nmap", event_type="service_discovery",
                source_ip="10.0.0.5", destination_ip="10.0.0.20",
                destination_port=port, protocol="tcp", severity="low", confidence=0.9,
            ))

        detections = run_detection(self.db)
        self.assertTrue(any(d.event_type == "port_scan" for d in detections))

        incident_ids = correlate(self.db, detections)
        self.assertEqual(len(incident_ids), 1)

        score, severity, breakdown = compute_risk(self.db, incident_ids[0])
        self.assertGreaterEqual(score, 20)
        self.assertIn(("Port scan", 20), breakdown)

        # The raw service_discovery events should have been pulled into
        # the incident too, not just the synthetic port_scan event.
        linked = self.db.get_incident_events(incident_ids[0])
        self.assertGreater(len(linked), 10)

    def test_below_threshold_produces_no_detection(self):
        for port in range(20, 25):  # only 5 ports, below threshold
            self.db.insert_event(NexusEvent(
                source="nmap", event_type="service_discovery",
                source_ip="10.0.0.9", destination_ip="10.0.0.20",
                destination_port=port, protocol="tcp", severity="low", confidence=0.9,
            ))
        detections = run_detection(self.db)
        self.assertFalse(any(d.event_type == "port_scan" and d.source_ip == "10.0.0.9"
                              for d in detections))

    def test_multi_factor_incident_scores_higher(self):
        base_ip = "10.0.0.15"
        for port in range(1, 13):
            self.db.insert_event(NexusEvent(
                source="nmap", event_type="service_discovery",
                source_ip=base_ip, destination_ip="10.0.0.20",
                destination_port=port, protocol="tcp", severity="low", confidence=0.9,
            ))
        # sensitive service (22 is in SENSITIVE_PORTS)
        self.db.insert_event(NexusEvent(
            source="nmap", event_type="service_discovery",
            source_ip=base_ip, destination_ip="10.0.0.20",
            destination_port=22, protocol="tcp", severity="low", confidence=0.9,
        ))
        for _ in range(6):
            self.db.insert_event(NexusEvent(
                source="linux", event_type="login_failure",
                source_ip=base_ip, destination_ip="10.0.0.20",
                severity="medium", confidence=0.8,
            ))

        detections = run_detection(self.db)
        incident_ids = correlate(self.db, detections)
        self.assertEqual(len(incident_ids), 1)  # same IP -> same incident, not two

        score, severity, breakdown = compute_risk(self.db, incident_ids[0])
        factor_labels = [label for label, _ in breakdown]
        self.assertIn("Port scan", factor_labels)
        self.assertIn("Sensitive service exposed", factor_labels)
        self.assertIn("Repeated authentication failures", factor_labels)
        self.assertGreaterEqual(score, 50)
        self.assertIn(severity, ("high", "critical"))


    def test_stale_incident_does_not_absorb_new_unrelated_activity(self):
        base_ip = "10.0.0.42"
        for port in range(1, 12):
            self.db.insert_event(NexusEvent(
                source="nmap", event_type="service_discovery",
                source_ip=base_ip, destination_ip="10.0.0.20",
                destination_port=port, protocol="tcp", severity="low", confidence=0.9,
            ))
        detections = run_detection(self.db)
        first_incident_ids = correlate(self.db, detections)
        self.assertEqual(len(first_incident_ids), 1)
        old_incident_id = first_incident_ids[0]

        # Simulate this incident having gone stale (nobody touched it
        # in a long time) by backdating updated_at past the TTL.
        from analyzers import rules
        stale_time = (datetime.now(timezone.utc)
                       - timedelta(seconds=rules.CORRELATION_TTL_SECONDS + 60)).isoformat()
        with self.db._conn:
            self.db._conn.execute(
                "UPDATE incidents SET updated_at = ? WHERE incident_id = ?",
                (stale_time, old_incident_id),
            )

        # New port-scan activity on the SAME ip should now open a NEW
        # incident rather than silently attaching to the stale one.
        for port in range(50, 62):
            self.db.insert_event(NexusEvent(
                source="nmap", event_type="service_discovery",
                source_ip=base_ip, destination_ip="10.0.0.20",
                destination_port=port, protocol="tcp", severity="low", confidence=0.9,
            ))
        detections2 = run_detection(self.db)
        second_incident_ids = correlate(self.db, detections2)
        self.assertEqual(len(second_incident_ids), 1)
        self.assertNotEqual(second_incident_ids[0], old_incident_id)

    def test_resolved_incident_is_not_reused_even_when_fresh(self):
        base_ip = "10.0.0.43"
        for port in range(1, 12):
            self.db.insert_event(NexusEvent(
                source="nmap", event_type="service_discovery",
                source_ip=base_ip, destination_ip="10.0.0.20",
                destination_port=port, protocol="tcp", severity="low", confidence=0.9,
            ))
        detections = run_detection(self.db)
        incident_id = correlate(self.db, detections)[0]
        self.db.update_incident_status(incident_id, "RESOLVED")

        for port in range(80, 92):
            self.db.insert_event(NexusEvent(
                source="nmap", event_type="service_discovery",
                source_ip=base_ip, destination_ip="10.0.0.20",
                destination_port=port, protocol="tcp", severity="low", confidence=0.9,
            ))
        detections2 = run_detection(self.db)
        new_incident_id = correlate(self.db, detections2)[0]
        self.assertNotEqual(new_incident_id, incident_id)
        self.assertEqual(self.db.get_incident(incident_id)["status"], "RESOLVED")


if __name__ == "__main__":
    unittest.main()

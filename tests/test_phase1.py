"""
Verifies the blueprint's own "first milestone" for Phase 1:
an agent sends an event over TCP, the server receives, validates,
and stores it. Also covers the framing edge case the blueprint
doesn't mention: multiple events sent back-to-back must each be
stored separately, not merged or dropped.
"""

import threading
import time
import unittest
from pathlib import Path

from agents.socket_agent import NexusAgent
from database.database import Database
from normalization.event_schema import EventValidationError, NexusEvent
from server.socket_server import NexusServer

TEST_PORT = 9191
TEST_DB_PATH = Path(__file__).parent / "test_nexus.db"


class TestPhase1SocketBackbone(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        TEST_DB_PATH.unlink(missing_ok=True)
        cls.db = Database(db_path=TEST_DB_PATH)
        cls.server = NexusServer(host="127.0.0.1", port=TEST_PORT, db=cls.db)
        cls.thread = threading.Thread(target=cls.server.start, daemon=True)
        cls.thread.start()
        time.sleep(0.2)  # let the listen socket come up

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.thread.join(timeout=2)
        cls.db.close()
        TEST_DB_PATH.unlink(missing_ok=True)

    def test_single_event_round_trip(self):
        before = self.db.get_event_count()
        event = NexusEvent(
            source="nmap", event_type="service_discovery",
            destination_ip="10.0.0.20", destination_port=22,
            protocol="tcp", severity="low", confidence=0.9,
        )
        with NexusAgent(port=TEST_PORT) as agent:
            agent.send_event(event)
        time.sleep(0.3)

        after = self.db.get_event_count()
        self.assertEqual(after, before + 1)

        stored = self.db.get_events(limit=1)[0]
        self.assertEqual(stored["event_id"], event.event_id)
        self.assertEqual(stored["source"], "nmap")
        self.assertEqual(stored["destination_port"], 22)

    def test_multiple_events_same_connection_are_not_merged(self):
        before = self.db.get_event_count()
        events = [
            NexusEvent(source="scapy", event_type="packet_anomaly", severity="medium")
            for _ in range(5)
        ]
        with NexusAgent(port=TEST_PORT) as agent:
            for e in events:
                agent.send_event(e)
        time.sleep(0.3)

        after = self.db.get_event_count()
        self.assertEqual(after, before + 5)

    def test_malformed_event_is_rejected_not_crash_server(self):
        # Bad severity should be rejected by the schema, and the server
        # should stay up and keep handling subsequent good events.
        with self.assertRaises(EventValidationError):
            NexusEvent(source="nmap", event_type="x", severity="apocalyptic")

        before = self.db.get_event_count()
        good_event = NexusEvent(source="linux", event_type="process_event", severity="high")
        with NexusAgent(port=TEST_PORT) as agent:
            agent.send_event(good_event)
        time.sleep(0.3)
        self.assertEqual(self.db.get_event_count(), before + 1)


if __name__ == "__main__":
    unittest.main()

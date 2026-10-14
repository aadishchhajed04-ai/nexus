"""
Phase 1 — Socket backbone (server side).

Listens for agent connections, reads newline-delimited JSON events,
validates them against the NEXUS event schema, and stores valid ones.
One thread per connected agent — fine for a handful of collectors;
if NEXUS ever needs hundreds of concurrent agents this should move to
asyncio, but that's premature for the current scope.
"""

from __future__ import annotations

import logging
import socket
import threading
from typing import Callable, Optional

from database.database import Database
from normalization.event_schema import EventValidationError, NexusEvent
from server.config import HOST, MAX_BUFFER_BYTES, MESSAGE_DELIMITER, PORT, RECV_CHUNK_SIZE

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("nexus.server")


class NexusServer:
    def __init__(
        self,
        host: str = HOST,
        port: int = PORT,
        db: Database | None = None,
        on_event: Optional[Callable[[NexusEvent], None]] = None,
    ):
        self.host = host
        self.port = port
        self.db = db or Database()
        # Called after an event is successfully validated and stored.
        # This is how the REST/WebSocket layer (a separate module, kept
        # separate on purpose) hooks the detection→correlation→risk
        # pipeline and live dashboard updates onto raw ingestion without
        # the socket server needing to know either of those exist.
        self.on_event = on_event
        self._sock: socket.socket | None = None
        self._running = threading.Event()

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen()
        self._running.set()
        log.info(f"NEXUS server listening on {self.host}:{self.port}")

        try:
            while self._running.is_set():
                try:
                    conn, addr = self._sock.accept()
                except OSError:
                    # Socket was closed by stop() while blocked in accept().
                    break
                thread = threading.Thread(
                    target=self._handle_connection, args=(conn, addr), daemon=True
                )
                thread.start()
        finally:
            if self._sock:
                self._sock.close()

    def stop(self) -> None:
        self._running.clear()
        if self._sock:
            try:
                # Unblocks a thread stuck in accept().
                self._sock.close()
            except OSError:
                pass

    def _handle_connection(self, conn: socket.socket, addr) -> None:
        log.info(f"Agent connected: {addr}")
        buffer = b""
        try:
            with conn:
                while True:
                    chunk = conn.recv(RECV_CHUNK_SIZE)
                    if not chunk:
                        break  # Agent closed the connection.
                    buffer += chunk
                    if len(buffer) > MAX_BUFFER_BYTES:
                        log.warning(f"Agent {addr} exceeded buffer limit, dropping connection.")
                        return

                    while MESSAGE_DELIMITER in buffer:
                        line, buffer = buffer.split(MESSAGE_DELIMITER, 1)
                        if line.strip():
                            self._process_line(line, addr)
        except ConnectionResetError:
            pass
        finally:
            log.info(f"Agent disconnected: {addr}")

    def _process_line(self, line: bytes, addr) -> None:
        try:
            event = NexusEvent.from_json(line.decode("utf-8"))
        except (EventValidationError, UnicodeDecodeError) as exc:
            log.warning(f"Rejected malformed event from {addr}: {exc}")
            return

        self.db.insert_event(event)
        log.info(
            f"Received event: {event.event_type} "
            f"(source={event.source}, severity={event.severity}, id={event.event_id[:8]})"
        )
        if self.on_event is not None:
            try:
                self.on_event(event)
            except Exception:
                log.exception("on_event hook raised — ingestion continues regardless.")


if __name__ == "__main__":
    server = NexusServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()

"""
Central configuration for the NEXUS socket backbone.

Keep this as the single source of truth for host/port/framing settings
so the server and every agent agree on how to talk to each other.
"""

HOST = "127.0.0.1"
PORT = 9090

# Messages are newline-delimited JSON (NDJSON): one JSON object per line.
# TCP has no built-in message boundaries, so without an explicit framing
# scheme, two fast events can arrive concatenated in a single recv(), or
# one event can be split across two recv() calls. Newline-delimiting is
# the simplest fix that works for arbitrarily long-running connections.
MESSAGE_DELIMITER = b"\n"

# Max bytes to buffer per connection before we consider it a malformed/
# malicious agent and drop it. Prevents an agent that never sends a
# newline from growing the server's memory unbounded.
MAX_BUFFER_BYTES = 1_000_000

RECV_CHUNK_SIZE = 4096

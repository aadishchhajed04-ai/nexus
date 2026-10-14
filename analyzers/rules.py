"""Phase 6 — configurable detection thresholds."""

PORT_SCAN_THRESHOLD = 10       # distinct destination ports from one source
CONNECTION_THRESHOLD = 50      # connections from one source
AUTH_FAILURE_THRESHOLD = 5     # login failures from one source
TIME_WINDOW_SECONDS = 60

# How long an OPEN incident keeps absorbing new events for the same IP
# before correlation treats it as stale and starts a fresh incident
# instead. Without this, one old OPEN incident nobody ever resolved
# would silently vacuum up unrelated activity on that IP forever.
CORRELATION_TTL_SECONDS = 300

SENSITIVE_PORTS = {21, 22, 23, 25, 139, 445, 1433, 3306, 3389, 5432, 5900}

SUSPICIOUS_HTTP_PATTERNS = [
    "' OR '1'='1",
    "<script>",
    "../../../",
    "UNION SELECT",
    "; DROP TABLE",
]

"""
Phase 12 — CAPA collector.

Honest caveat, stated once here instead of buried: this collector
could NOT be end-to-end tested in the build sandbox — `capa` needs its
rules repository and a real PE/ELF sample to analyze, neither of which
belong in an automated sandbox run. The parsing logic below is written
against capa's documented `-j` JSON output schema, but treat it as
untested against a real `capa` binary until you run it once locally
and confirm the output shape matches.

Also, per the blueprint's own note: CAPA is a static capability
analyzer, not an intrusion detection system, and analyzing real
malware samples needs an isolated, air-gapped VM — don't run this
against anything you're not fully set up to handle safely.
"""

from __future__ import annotations

import json
import subprocess

from normalization.event_schema import NexusEvent


class CapaCollectorError(RuntimeError):
    pass


def run_capa_analysis(file_path: str) -> NexusEvent:
    cmd = ["capa", "-j", file_path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=True)
    except FileNotFoundError as exc:
        raise CapaCollectorError(
            "capa binary not found on PATH. Install: pip install flare-capa "
            "(and download its rules repo — see capa's own setup docs)."
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise CapaCollectorError(f"capa exited with error: {exc.stderr}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CapaCollectorError("capa analysis timed out.") from exc

    return parse_capa_json(result.stdout, file_path)


def parse_capa_json(json_text: str, file_path: str) -> NexusEvent:
    try:
        payload = json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise CapaCollectorError(f"Could not parse capa JSON output: {exc}") from exc

    # capa's JSON nests matched rules under rules -> {rule_name: {...}}.
    # We only pull out rule names as "capabilities" — good enough for
    # correlation/risk purposes without depending on capa's full,
    # fairly deep result structure.
    capabilities = list(payload.get("rules", {}).keys())

    severity = "medium" if capabilities else "low"
    return NexusEvent(
        source="capa",
        event_type="file_analysis",
        severity=severity,
        confidence=0.8 if capabilities else 0.5,
        data={"file": file_path, "capabilities": capabilities},
    )

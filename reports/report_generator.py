"""
Phase 17 — Report generation.

generate_markdown_report() is the primary output — it's what the
dashboard's "Reports" page and the demo scenarios actually need.
generate_pdf_report() wraps the same content in a simple PDF for
"send this to someone who wants a PDF" cases; it intentionally does
not duplicate the markdown's content logic, just its rendering.
"""

from __future__ import annotations

import json

from database.database import Database
from mitre.attack_mapping import map_technique


def _gather(db: Database, incident_id: int) -> dict:
    incident = db.get_incident(incident_id)
    if incident is None:
        raise ValueError(f"No incident with id {incident_id}")
    events = db.get_incident_events(incident_id)
    return {"incident": incident, "events": events}


def generate_markdown_report(db: Database, incident_id: int) -> str:
    data = _gather(db, incident_id)
    incident, events = data["incident"], data["events"]

    lines = [
        f"# Incident Report — INC-{incident_id:04d}",
        "",
        f"**Title:** {incident['title']}",
        f"**Risk score:** {incident['risk_score']} ({incident['severity'].upper()})",
        f"**Status:** {incident['status']}",
        f"**Created:** {incident['created_at']}",
        f"**Last updated:** {incident['updated_at']}",
        "",
        "> The risk score is an internal investigation-prioritization score, "
        "not a scientifically validated probability.",
        "",
        "## Timeline",
        "",
    ]

    for e in events:
        lines.append(f"- `{e['timestamp']}` **{e['event_type']}** "
                      f"(source: {e['source']}, severity: {e['severity']})"
                      + (f" — {e['source_ip']} → {e['destination_ip']}"
                         if e['source_ip'] or e['destination_ip'] else ""))

    lines += ["", "## Evidence", ""]
    for e in events:
        try:
            raw = json.loads(e["raw_data"] or "{}")
        except json.JSONDecodeError:
            raw = {}
        lines.append(f"### Event `{e['event_id'][:8]}` — {e['event_type']}")
        lines.append(f"- Source: {e['source']}")
        if e["destination_port"]:
            lines.append(f"- Port: {e['destination_port']}/{e['protocol'] or '?'}")
        if raw.get("data"):
            lines.append(f"- Data: `{json.dumps(raw['data'])}`")
        lines.append("")

    lines += ["## MITRE ATT&CK Mapping", ""]
    mapped_any = False
    for e in events:
        technique = map_technique(e["event_type"])
        if technique:
            mapped_any = True
            lines.append(f"- {e['event_type']} → **{technique['technique_id']}** "
                          f"({technique['technique_name']})")
    if not mapped_any:
        lines.append("_No events in this incident had a confident technique mapping._")

    lines += [
        "",
        "## Analysis",
        "",
        f"This incident was created from a '{incident['description']}'.",
        "",
        "## Conclusion",
        "",
        "This report describes the observed activity and the evidence that "
        "supports it. It does not claim certainty beyond what the linked "
        "events show — treat the risk score as a prioritization aid, and "
        "verify packet-level claims directly in Wireshark before acting on them.",
    ]

    return "\n".join(lines)


def generate_pdf_report(db: Database, incident_id: int, output_path: str) -> str:
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet

    markdown_text = generate_markdown_report(db, incident_id)
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(output_path, pagesize=LETTER)
    story = []
    for line in markdown_text.split("\n"):
        if line.startswith("# "):
            story.append(Paragraph(line[2:], styles["Title"]))
        elif line.startswith("## "):
            story.append(Paragraph(line[3:], styles["Heading2"]))
        elif line.startswith("### "):
            story.append(Paragraph(line[4:], styles["Heading3"]))
        elif line.strip():
            story.append(Paragraph(line, styles["BodyText"]))
        else:
            story.append(Spacer(1, 0.15 * inch))
    doc.build(story)
    return output_path

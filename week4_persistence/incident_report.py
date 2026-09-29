"""
incident_report.py
---------------------
WHY THIS FILE EXISTS:
A CloudOps team's compliance/audit process needs a paper trail, not just a
terminal that scrolled past five minutes ago. This module turns one
detection + remediation cycle into a clean, shareable PDF: what drifted,
exactly which rule caused it, the exact code AeroDrift wrote to fix it, and
proof the fix worked -- everything an incident review meeting or a SOC2
auditor would ask for.
"""
import os
import textwrap
from datetime import datetime, timezone

from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, Preformatted,
)


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="AeroTitle", fontSize=22, leading=26, textColor=colors.HexColor("#0F172A"),
        spaceAfter=4, fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="AeroSubtitle", fontSize=11, textColor=colors.HexColor("#64748B"),
        spaceAfter=18,
    ))
    styles.add(ParagraphStyle(
        name="AeroSectionHead", fontSize=13, textColor=colors.HexColor("#0F172A"),
        fontName="Helvetica-Bold", spaceBefore=18, spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="AeroBody", fontSize=10, textColor=colors.HexColor("#1E293B"), leading=15,
    ))
    styles.add(ParagraphStyle(
        name="AeroCritical", fontSize=10.5, textColor=colors.HexColor("#B91C1C"),
        fontName="Helvetica-Bold", leading=15,
    ))
    styles.add(ParagraphStyle(
        name="AeroGood", fontSize=10.5, textColor=colors.HexColor("#15803D"),
        fontName="Helvetica-Bold", leading=15,
    ))
    return styles


def generate_incident_report(
    output_path: str,
    drift_events: list,
    remediation_events: list,
    generated_code: str,
    detection_ms: float,
    remediation_ms: float,
) -> str:
    """Builds one PDF incident report from a single detect -> remediate
    cycle's real results. Returns the output_path for convenience."""
    if os.path.dirname(output_path):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

    styles = _build_styles()
    doc = SimpleDocTemplate(
        output_path, pagesize=LETTER,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.85 * inch, rightMargin=0.85 * inch,
    )

    story = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    story.append(Paragraph("AeroDrift Incident Report", styles["AeroTitle"]))
    story.append(Paragraph(f"Autonomous drift detection &amp; remediation &middot; generated {now}", styles["AeroSubtitle"]))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#E2E8F0"), thickness=1))

    # --- Summary table ---
    story.append(Paragraph("Summary", styles["AeroSectionHead"]))
    critical_count = sum(1 for e in drift_events if e.severity == "CRITICAL")
    summary_data = [
        ["Findings", str(len(drift_events))],
        ["Critical findings", str(critical_count)],
        ["Detection time", f"{detection_ms:.2f} ms"],
        ["Remediation time", f"{remediation_ms:.3f} ms"],
        ["Remediations confirmed", str(len(remediation_events))],
    ]
    summary_table = Table(summary_data, colWidths=[2.4 * inch, 3 * inch])
    summary_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1E293B")),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)

    # --- What drifted ---
    story.append(Paragraph("What Drifted", styles["AeroSectionHead"]))
    if not drift_events:
        story.append(Paragraph("No dangerous drift was detected in this scan.", styles["AeroGood"]))
    for e in drift_events:
        style = styles["AeroCritical"] if e.severity == "CRITICAL" else styles["AeroBody"]
        story.append(Paragraph(f"[{e.severity}] {e.description}", style))
        if e.exposure_path:
            story.append(Paragraph(
                f"Exposure path: {' &rarr; '.join(e.exposure_path)}",
                styles["AeroBody"],
            ))
        story.append(Spacer(1, 6))

    # --- Generated remediation code ---
    story.append(Paragraph("Autonomously Generated Remediation", styles["AeroSectionHead"]))
    story.append(Paragraph(
        "AeroDrift built the following code with Python's <b>ast</b> module (not a string "
        "template) and executed it inside a locked-down sandbox with no builtin access:",
        styles["AeroBody"],
    ))
    story.append(Spacer(1, 6))
    code_style = ParagraphStyle(
        name="Code", fontName="Courier", fontSize=8.5, leading=12,
        backColor=colors.HexColor("#0F172A"), textColor=colors.HexColor("#7DD3FC"),
        borderPadding=10,
    )
    wrapped_code = textwrap.fill(generated_code, width=88, subsequent_indent="    ") \
        if generated_code else "(no remediation was necessary)"
    story.append(Preformatted(wrapped_code, code_style))

    # --- Verification ---
    story.append(Paragraph("Verification", styles["AeroSectionHead"]))
    if remediation_events:
        for e in remediation_events:
            story.append(Paragraph(f"[REMEDIATED] {e.description}", styles["AeroGood"]))
    else:
        story.append(Paragraph("No remediation was recorded for this cycle.", styles["AeroBody"]))

    doc.build(story)
    return output_path


if __name__ == "__main__":
    import sys

    sys.path.append(os.path.join(os.path.dirname(__file__), "..", "week1_ingestion"))
    sys.path.append(os.path.join(os.path.dirname(__file__), "..", "week2_drift_detection"))
    sys.path.append(os.path.join(os.path.dirname(__file__), "..", "week3_remediation"))
    from mock_aws_environment import get_baseline_state, inject_drift_open_db_to_internet
    from topology_graph import build_topology_graph
    from drift_detector import detect_drift, detect_remediation
    from mock_aws_client import MockAWSClient
    from code_generator import generate_remediation
    from execution_sandbox import run_remediation_safely
    import time

    baseline_graph = build_topology_graph(get_baseline_state())
    live_state = inject_drift_open_db_to_internet(get_baseline_state())
    client = MockAWSClient(live_state)

    t0 = time.perf_counter()
    current_graph = build_topology_graph(client.state)
    events = detect_drift(baseline_graph, current_graph)
    detection_ms = (time.perf_counter() - t0) * 1000

    source, code_obj, group_id, rule = generate_remediation(current_graph, "i-db01")
    t1 = time.perf_counter()
    run_remediation_safely(code_obj, client)
    remediation_ms = (time.perf_counter() - t1) * 1000

    healed_graph = build_topology_graph(client.state)
    remediation_events = detect_remediation(current_graph, healed_graph)

    out = os.path.join(os.path.dirname(__file__), "..", "reports", "incident_001.pdf")
    path = generate_incident_report(out, events, remediation_events, source, detection_ms, remediation_ms)
    print(f"Wrote incident report to {path}")

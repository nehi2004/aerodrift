"""
main.py
--------
The complete AeroDrift daemon cycle, exactly as described in the project's
use case: ingest current cloud state, detect dangerous drift against the
last known-good snapshot, autonomously generate and run the exact fix,
persist everything to SQLite, and produce a PDF incident report -- all
without a human in the loop.

USAGE:
    python main.py                      # run one full detect-and-heal cycle
    python main.py --history            # list every saved snapshot
    python main.py --diff 1 2           # diff two saved snapshots by id
"""
import argparse
import asyncio
import os
import sys
import time

sys.path.append(os.path.join(os.path.dirname(__file__), "week1_ingestion"))
sys.path.append(os.path.join(os.path.dirname(__file__), "week2_drift_detection"))
sys.path.append(os.path.join(os.path.dirname(__file__), "week3_remediation"))
sys.path.append(os.path.join(os.path.dirname(__file__), "week4_persistence"))

from mock_aws_environment import get_baseline_state, inject_drift_open_db_to_internet
from aws_ingestion import ingest_cloud_state
from topology_graph import build_topology_graph, is_directly_exposed_to_internet
from drift_detector import detect_drift, detect_remediation
from mock_aws_client import MockAWSClient
from code_generator import generate_remediation
from execution_sandbox import run_remediation_safely, RemediationError
from state_history import init_db, save_snapshot, list_snapshots, diff_snapshot_pair
from incident_report import generate_incident_report

try:
    from rich_dashboard import console, build_topology_tree, render_drift_panel, render_gpu_style_summary
    RICH_AVAILABLE = True
except Exception:
    RICH_AVAILABLE = False

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "aerodrift_history.db")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")


async def run_full_cycle():
    init_db(DB_PATH)

    # --- ingest the secure baseline (in a real daemon this would be the
    # last snapshot that passed a clean scan; here we regenerate it fresh
    # each run so the demo is self-contained) ---
    baseline_state = await ingest_cloud_state(get_baseline_state())
    baseline_graph = build_topology_graph(baseline_state)
    baseline_id = save_snapshot(DB_PATH, baseline_state, label="secure baseline")

    # --- simulate the incident: an engineer opens the DB to the internet ---
    live_source = inject_drift_open_db_to_internet(get_baseline_state())
    live_state = await ingest_cloud_state(live_source)
    client = MockAWSClient(live_state)

    t0 = time.perf_counter()
    current_graph = build_topology_graph(client.state)
    events = detect_drift(baseline_graph, current_graph)
    detection_ms = (time.perf_counter() - t0) * 1000

    drifted_id = save_snapshot(DB_PATH, client.state, label="drift detected")

    critical_events = [e for e in events if e.severity == "CRITICAL"]
    generated_source = None
    remediation_ms = 0.0

    for event in critical_events:
        source, code_obj, group_id, rule = generate_remediation(current_graph, event.instance_id)
        if source is None:
            continue
        generated_source = source
        t1 = time.perf_counter()
        try:
            run_remediation_safely(code_obj, client)
        except RemediationError as e:
            print(f"Remediation failed for {event.instance_label}: {e}")
            continue
        remediation_ms = (time.perf_counter() - t1) * 1000

    healed_graph = build_topology_graph(client.state)
    remediation_events = detect_remediation(current_graph, healed_graph)
    healed_id = save_snapshot(DB_PATH, client.state, label="post-remediation (healed)")

    report_path = os.path.join(REPORTS_DIR, f"incident_{drifted_id:03d}.pdf")
    generate_incident_report(report_path, events, remediation_events, generated_source,
                              detection_ms, remediation_ms or 0.0)

    # --- render results ---
    if RICH_AVAILABLE:
        console.rule("[bold red]AeroDrift — Full Cycle Result[/bold red]")
        console.print(render_gpu_style_summary(healed_graph))
        console.print(build_topology_tree(healed_graph, "Post-Remediation Topology"))
        console.print(render_drift_panel(events))
        console.print(f"[bold green]Incident report saved:[/bold green] {report_path}")
    else:
        print(f"\nSnapshots saved: baseline=#{baseline_id}, drifted=#{drifted_id}, healed=#{healed_id}")
        print(f"Detection: {detection_ms:.2f}ms | Remediation: {remediation_ms:.3f}ms")
        print(f"Incident report saved: {report_path}")


def show_history():
    init_db(DB_PATH)
    snapshots = list_snapshots(DB_PATH)
    if not snapshots:
        print("No snapshots saved yet -- run `python main.py` first.")
        return
    for s in snapshots:
        label = s["label"] or "(no label)"
        print(f"  #{s['id']:<4} {s['taken_at']}  -- {label}")


def show_diff(id_a: int, id_b: int):
    result = diff_snapshot_pair(DB_PATH, id_a, id_b)
    print(f"Diff: snapshot #{id_a} -> #{id_b}")
    if not result["new_dangers"] and not result["remediations"]:
        print("  No security-relevant change between these snapshots.")
    for e in result["new_dangers"]:
        print(f"  \U0001F534 [{e.severity}] {e.description}")
    for e in result["remediations"]:
        print(f"  \U0001F7E2 {e.description}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AeroDrift — Agentic Cloud Topology & Remediation Graph")
    parser.add_argument("--history", action="store_true", help="List every saved snapshot.")
    parser.add_argument("--diff", nargs=2, type=int, metavar=("FROM_ID", "TO_ID"),
                         help="Diff two saved snapshots by id.")
    args = parser.parse_args()

    if args.history:
        show_history()
    elif args.diff:
        show_diff(*args.diff)
    else:
        asyncio.run(run_full_cycle())
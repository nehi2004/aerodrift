"""
self_heal_demo.py
--------------------
WHY THIS FILE EXISTS:
This is the end-to-end story the whole project is built around, exactly as
described in the use case: a security group drifts open, and AeroDrift
detects it, writes the exact fix itself, runs that fix safely, and proves
the fix worked -- with no human in the loop and no PR/CI pipeline.

PIPELINE:
    1. Ingest the (drifted) current cloud state       [Week 1]
    2. Build the topology graph, diff against baseline  [Week 1 + 2]
    3. Find the exact offending rule                    [Week 3]
    4. Generate the exact revocation code via ast        [Week 3]
    5. Execute it in a locked-down sandbox               [Week 3]
    6. Re-ingest + re-diff to CONFIRM the fix worked      [Week 2]

Every step prints real, measured timing -- this file is the "wow" demo to
run live.
"""
import asyncio
import time
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "week1_ingestion"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "week2_drift_detection"))
sys.path.append(os.path.dirname(__file__))

from mock_aws_environment import get_baseline_state, inject_drift_open_db_to_internet
from topology_graph import build_topology_graph, is_directly_exposed_to_internet
from drift_detector import detect_drift, detect_remediation
from mock_aws_client import MockAWSClient
from code_generator import generate_remediation
from execution_sandbox import run_remediation_safely, RemediationError


async def main():
    total_start = time.perf_counter()

    # ---- Step 1: establish the secure baseline (what "correct" looks like) ----
    baseline_state = get_baseline_state()
    baseline_graph = build_topology_graph(baseline_state)
    print("[1/6] Secure baseline established.")

    # ---- Step 2: simulate the incident -- an engineer drifts the DB open ----
    live_state = inject_drift_open_db_to_internet(get_baseline_state())
    client = MockAWSClient(live_state)   # the ONE mutable "live cloud" the daemon watches
    print("[2/6] Drift injected: db-sg accidentally opened to 0.0.0.0/0 (simulating a manual console change).")

    # ---- Step 3: daemon polls current state and rebuilds its graph ----
    detect_start = time.perf_counter()
    current_graph = build_topology_graph(client.state)
    events = detect_drift(baseline_graph, current_graph)
    detect_elapsed = time.perf_counter() - detect_start

    critical_events = [e for e in events if e.severity == "CRITICAL"]
    print(f"[3/6] Drift scan complete in {detect_elapsed*1000:.2f}ms -- "
          f"{len(critical_events)} CRITICAL finding(s):")
    for e in critical_events:
        print(f"        \U0001F534 {e.description}")

    if not critical_events:
        print("Nothing critical detected -- stopping (no remediation needed).")
        return

    # ---- Step 4 & 5: for each critical finding, generate + run the fix ----
    for event in critical_events:
        print(f"\n[4/6] Generating remediation code for {event.instance_label}...")
        source, code_obj, group_id, rule = generate_remediation(current_graph, event.instance_id)

        if source is None:
            print("        Could not identify a specific offending rule -- skipping.")
            continue

        print("        Generated code (via Python's ast module, not a string template):")
        print(f"        > {source}")

        print(f"\n[5/6] Executing remediation inside the locked-down sandbox...")
        try:
            result = run_remediation_safely(code_obj, client)
            print(f"        Executed successfully in {result['elapsed_seconds']*1000:.3f}ms.")
        except RemediationError as e:
            print(f"        REMEDIATION FAILED: {e}")
            continue

    # ---- Step 6: re-poll and confirm the fix actually worked ----
    healed_graph = build_topology_graph(client.state)
    still_exposed = is_directly_exposed_to_internet(healed_graph, "i-db01")
    remediation_events = detect_remediation(current_graph, healed_graph)

    print(f"\n[6/6] Verification:")
    if still_exposed:
        print("        \u274C prod-database-01 is STILL directly exposed -- remediation did not take effect.")
    else:
        print("        \u2705 prod-database-01 is no longer directly exposed to the internet.")
    for e in remediation_events:
        print(f"        \U0001F7E2 {e.description}")

    total_elapsed = time.perf_counter() - total_start
    print(f"\nTotal time from drift injection to verified self-heal: {total_elapsed*1000:.2f}ms")


if __name__ == "__main__":
    asyncio.run(main())

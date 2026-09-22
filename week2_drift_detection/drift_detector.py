"""
drift_detector.py
--------------------
WHY THIS FILE EXISTS:
Week 1 answers "is this instance exposed RIGHT NOW". This module answers the
question a real CloudOps engineer actually cares about: "what CHANGED, and
did it make anything MORE dangerous than it was a moment ago?"

Comparing two full graphs node-by-node would be noisy -- most differences
(a new EC2 instance being launched, a subnet being added) are completely
routine and not security incidents. AeroDrift's drift detector deliberately
narrows in on ONE category of change: newly-appeared "ingress" edges,
especially ones that make a previously-safe instance directly reachable
from the internet. That is the specific, narrow signal the project brief
describes -- not a generic diff tool.
"""
import time
from dataclasses import dataclass, field
from typing import Optional
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "week1_ingestion"))
from topology_graph import (
    build_topology_graph, is_directly_exposed_to_internet,
    has_transitive_reachability, find_exposure_path, describe_path, INTERNET_NODE,
)


@dataclass
class DriftEvent:
    """One detected, security-relevant change between two snapshots."""
    severity: str            # "CRITICAL" | "WARNING" | "INFO"
    instance_id: str
    instance_label: str
    description: str
    exposure_path: Optional[list] = field(default=None)
    offending_edge: Optional[tuple] = None   # (source_node, target_sg, rule_port) that caused it


def _edge_set(graph, kind_filter=None):
    """Returns the graph's edges as a set of (u, v) tuples, optionally
    restricted to one edge 'kind' (e.g. only 'ingress' edges)."""
    if kind_filter is None:
        return set(graph.edges())
    return {(u, v) for u, v, d in graph.edges(data=True) if d.get("kind") == kind_filter}


def diff_ingress_edges(old_graph, new_graph) -> dict:
    """Low-level diff: which ingress edges (network-reachability rules)
    were added or removed between the two snapshots."""
    old_ingress = _edge_set(old_graph, "ingress")
    new_ingress = _edge_set(new_graph, "ingress")
    return {
        "added": sorted(new_ingress - old_ingress),
        "removed": sorted(old_ingress - new_ingress),
    }


def detect_drift(old_graph, new_graph) -> list:
    """The main entry point. Compares every instance's exposure status
    between the two graphs and returns a list of DriftEvent objects for
    anything that got MORE dangerous. Instances that got safer, or didn't
    change, are not reported here (see detect_remediation() for the
    opposite direction)."""
    events = []
    instances = [n for n, d in new_graph.nodes(data=True) if d.get("kind") == "instance"]

    for inst in instances:
        label = new_graph.nodes[inst].get("label", inst)

        was_direct = old_graph.has_node(inst) and is_directly_exposed_to_internet(old_graph, inst)
        is_direct_now = is_directly_exposed_to_internet(new_graph, inst)

        if is_direct_now and not was_direct:
            path = find_exposure_path(new_graph, inst)
            events.append(DriftEvent(
                severity="CRITICAL",
                instance_id=inst,
                instance_label=label,
                description=f"{label} became DIRECTLY reachable from the internet "
                             f"(it was not, in the previous snapshot).",
                exposure_path=path,
            ))
            continue

        was_transitive = old_graph.has_node(inst) and has_transitive_reachability(old_graph, inst)
        is_transitive_now = has_transitive_reachability(new_graph, inst)
        if is_transitive_now and not was_transitive:
            path = find_exposure_path(new_graph, inst)
            events.append(DriftEvent(
                severity="WARNING",
                instance_id=inst,
                instance_label=label,
                description=f"{label} is now reachable from the internet via tier-pivoting "
                             f"(new blast-radius exposure, not yet a direct incident).",
                exposure_path=path,
            ))

    return events


def detect_remediation(old_graph, new_graph) -> list:
    """The mirror image of detect_drift: reports instances that got SAFER
    between the two snapshots. Used in Week 3 to confirm a rollback
    actually worked."""
    events = []
    instances = [n for n, d in old_graph.nodes(data=True) if d.get("kind") == "instance"]

    for inst in instances:
        if not new_graph.has_node(inst):
            continue
        label = old_graph.nodes[inst].get("label", inst)
        was_direct = is_directly_exposed_to_internet(old_graph, inst)
        is_direct_now = is_directly_exposed_to_internet(new_graph, inst)

        if was_direct and not is_direct_now:
            events.append(DriftEvent(
                severity="INFO",
                instance_id=inst,
                instance_label=label,
                description=f"{label} is no longer directly exposed to the internet "
                             f"(remediation confirmed).",
            ))

    return events


def detect_drift_with_timing(old_state: dict, new_state: dict) -> tuple:
    """Wraps detect_drift with wall-clock timing, so the mid-project
    checkpoint claim -- 'detects new exposure paths in under 5 seconds' --
    is a measured number, not an assumption. Takes raw cloud STATE dicts
    (as ingested), builds both graphs, diffs them, and returns
    (events, elapsed_seconds)."""
    start = time.perf_counter()
    old_graph = build_topology_graph(old_state)
    new_graph = build_topology_graph(new_state)
    events = detect_drift(old_graph, new_graph)
    elapsed = time.perf_counter() - start
    return events, elapsed


if __name__ == "__main__":
    import asyncio

    sys.path.append(os.path.join(os.path.dirname(__file__), "..", "week1_ingestion"))
    from mock_aws_environment import get_baseline_state, inject_drift_open_db_to_internet
    from aws_ingestion import ingest_cloud_state

    async def main():
        baseline_state = await ingest_cloud_state(get_baseline_state())
        drifted_state = await ingest_cloud_state(inject_drift_open_db_to_internet(get_baseline_state()))

        events, elapsed = detect_drift_with_timing(baseline_state, drifted_state)

        print(f"Drift scan completed in {elapsed*1000:.2f}ms (requirement: under 5 seconds)\n")

        if not events:
            print("No new dangerous exposure detected.")
        for e in events:
            icon = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "🟢"}[e.severity]
            print(f"{icon} [{e.severity}] {e.description}")
            if e.exposure_path:
                old_graph = build_topology_graph(baseline_state)
                new_graph = build_topology_graph(drifted_state)
                print(f"    path: {describe_path(new_graph, e.exposure_path)}")

        ingress_diff = diff_ingress_edges(build_topology_graph(baseline_state), build_topology_graph(drifted_state))
        print(f"\nRaw ingress-edge diff: +{len(ingress_diff['added'])} added, -{len(ingress_diff['removed'])} removed")
        for u, v in ingress_diff["added"]:
            print(f"    NEW RULE: {u} -> {v}")

    asyncio.run(main())

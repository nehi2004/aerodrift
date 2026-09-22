"""
rich_dashboard.py
--------------------
WHY THIS FILE EXISTS:
A CloudOps engineer staring at a raw NetworkX graph object gets nothing
useful. This module renders that same graph as something a human can
actually read in one glance: an indented tree (VPC -> Subnet -> Instance),
with every instance color-coded by its real exposure status --
red for directly exposed, yellow for reachable-via-pivoting, green for safe
-- plus a separate panel summarizing exactly what changed.

Run this file directly to see the full Week 2 demo: baseline topology,
drifted topology, and the drift report that explains the difference.
"""
import sys
import os

from rich.console import Console
from rich.tree import Tree
from rich.panel import Panel
from rich.text import Text

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "week1_ingestion"))
from topology_graph import is_directly_exposed_to_internet, has_transitive_reachability, INTERNET_NODE

console = Console()


def _children(graph, node_id, kind):
    """Returns every node with an edge (child -> node_id) of the given
    'kind' -- i.e. every node's 'parent' in the containment hierarchy."""
    return [u for u, v, d in graph.in_edges(node_id, data=True) if d.get("kind") == kind]


def _attached_security_groups(graph, instance_id):
    return [u for u, v, d in graph.in_edges(instance_id, data=True) if d.get("kind") == "attached"]


def _instance_status_text(graph, instance_id) -> Text:
    label = graph.nodes[instance_id].get("label", instance_id)
    if is_directly_exposed_to_internet(graph, instance_id):
        return Text(f"● {label} — DIRECTLY EXPOSED TO INTERNET", style="bold red")
    if has_transitive_reachability(graph, instance_id):
        return Text(f"● {label} — reachable via tier pivoting", style="yellow")
    return Text(f"● {label} — not internet reachable", style="green")


def build_topology_tree(graph, title: str = "AeroDrift — Cloud Topology") -> Tree:
    """Builds a rich.tree.Tree mirroring the real VPC -> Subnet -> Instance
    hierarchy, reading the containment edges straight out of the graph
    rather than needing the original state dict again."""
    tree = Tree(f"🛰️  [bold cyan]{title}[/bold cyan]")

    vpc_nodes = [n for n, d in graph.nodes(data=True) if d.get("kind") == "vpc"]
    for vpc in vpc_nodes:
        vpc_label = graph.nodes[vpc].get("label", vpc)
        vpc_branch = tree.add(f"☁  [bold]VPC: {vpc_label}[/bold]  [dim]({vpc})[/dim]")

        for subnet in _children(graph, vpc, "contains"):
            is_public = graph.nodes[subnet].get("is_public", False)
            tag = "[bold green]public[/bold green]" if is_public else "[dim]private[/dim]"
            subnet_branch = vpc_branch.add(f"🔸 Subnet {subnet}  ({tag})")

            instance_nodes = [n for n in _children(graph, subnet, "contains")
                               if graph.nodes[n].get("kind") == "instance"]
            for inst in instance_nodes:
                sgs = _attached_security_groups(graph, inst)
                sg_labels = ", ".join(graph.nodes[sg].get("label", sg) for sg in sgs)
                status = _instance_status_text(graph, inst)
                leaf = subnet_branch.add(status)
                leaf.add(f"[dim]security group: {sg_labels}[/dim]")

    return tree


def render_drift_panel(events) -> Panel:
    """Builds a color-bordered summary panel from a list of DriftEvent
    objects (see drift_detector.py). Border color escalates to red the
    moment any CRITICAL event is present."""
    if not events:
        return Panel(
            "[green]✓ No new dangerous drift detected between snapshots.[/green]",
            title="Drift Report", border_style="green",
        )

    lines = []
    for e in events:
        color = {"CRITICAL": "bold red", "WARNING": "bold yellow", "INFO": "bold green"}[e.severity]
        icon = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "🟢"}[e.severity]
        lines.append(f"{icon} [{color}]{e.severity}[/{color}] — {e.description}")
        if e.exposure_path:
            path_str = " → ".join(e.exposure_path)
            lines.append(f"      [dim]path: {path_str}[/dim]")

    border = "red" if any(e.severity == "CRITICAL" for e in events) else "yellow"
    return Panel("\n".join(lines), title="🚨 Drift Report", border_style=border)


def render_gpu_style_summary(graph) -> Panel:
    """A quick top-line stats panel: total resources and how many are
    currently in each exposure state -- useful as the first thing an
    engineer sees before drilling into the tree."""
    instances = [n for n, d in graph.nodes(data=True) if d.get("kind") == "instance"]
    direct = sum(1 for i in instances if is_directly_exposed_to_internet(graph, i))
    transitive = sum(1 for i in instances if has_transitive_reachability(graph, i) and not is_directly_exposed_to_internet(graph, i))
    safe = len(instances) - direct - transitive

    text = (f"Instances: {len(instances)}   "
            f"[bold red]Direct exposure: {direct}[/bold red]   "
            f"[yellow]Tier-pivot reachable: {transitive}[/yellow]   "
            f"[green]Fully internal: {safe}[/green]")
    return Panel(text, title="Summary", border_style="cyan")


if __name__ == "__main__":
    import asyncio

    sys.path.append(os.path.join(os.path.dirname(__file__), "..", "week1_ingestion"))
    sys.path.append(os.path.dirname(__file__))
    from mock_aws_environment import get_baseline_state, inject_drift_open_db_to_internet
    from aws_ingestion import ingest_cloud_state
    from topology_graph import build_topology_graph
    from drift_detector import detect_drift_with_timing, detect_drift

    async def main():
        baseline_state = await ingest_cloud_state(get_baseline_state())
        drifted_state = await ingest_cloud_state(inject_drift_open_db_to_internet(get_baseline_state()))

        baseline_graph = build_topology_graph(baseline_state)
        drifted_graph = build_topology_graph(drifted_state)

        console.rule("[bold]SECURE BASELINE[/bold]")
        console.print(render_gpu_style_summary(baseline_graph))
        console.print(build_topology_tree(baseline_graph, "Baseline Topology"))

        console.rule("[bold red]AFTER DRIFT[/bold red]")
        console.print(render_gpu_style_summary(drifted_graph))
        console.print(build_topology_tree(drifted_graph, "Current Topology (drift injected)"))

        events = detect_drift(baseline_graph, drifted_graph)
        console.print(render_drift_panel(events))

    asyncio.run(main())

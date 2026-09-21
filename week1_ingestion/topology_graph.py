"""
topology_graph.py
--------------------
WHY THIS FILE EXISTS:
This is the heart of AeroDrift's "agentic" reasoning. Instead of looking at
security groups as a flat list of rules, we model the ENTIRE cloud as a
directed graph, where an edge A -> B means "traffic can flow from A to B".
Once the cloud is a graph, a question like "can anything on the internet
reach the production database?" stops being a manual rule-by-rule audit and
becomes a single, fast graph query: networkx.has_path(graph, "internet",
"i-db01").

NODE TYPES:
- "internet"        -- one single pseudo-node representing 0.0.0.0/0
- vpc_id             -- one node per VPC
- subnet_id          -- one node per subnet
- security_group_id  -- one node per security group
- instance_id        -- one node per EC2 instance

EDGE TYPES (edge attribute "kind" distinguishes them):
- "ingress"   internet -> security_group   (an SG rule allows 0.0.0.0/0)
- "ingress"   security_group -> security_group (an SG rule allows another SG as its source)
- "attached"  security_group -> instance    (the SG is attached to that instance)
- "contains"  instance -> subnet -> vpc     (purely structural, for the topology tree view)

Only "ingress" and "attached" edges represent actual network reachability
and are what path-finding queries care about; "contains" edges exist so
Week 2's Rich dashboard can render a sensible tree, and are dead ends that
never introduce false reachability paths (an instance's subnet/VPC never
leads back out to another instance).
"""
import networkx as nx

INTERNET_NODE = "internet"


def build_topology_graph(state: dict) -> nx.DiGraph:
    """Converts one cloud-state snapshot (as returned by aws_ingestion.py)
    into a NetworkX directed graph."""
    g = nx.DiGraph()
    g.add_node(INTERNET_NODE, kind="internet", label="Internet (0.0.0.0/0)")

    for vpc in state["vpcs"]:
        g.add_node(vpc["vpc_id"], kind="vpc", label=vpc.get("name", vpc["vpc_id"]))

    for subnet in state["subnets"]:
        g.add_node(subnet["subnet_id"], kind="subnet",
                   label=subnet["subnet_id"], is_public=subnet["is_public"])
        g.add_edge(subnet["subnet_id"], subnet["vpc_id"], kind="contains")

    for sg in state["security_groups"]:
        g.add_node(sg["group_id"], kind="security_group",
                   label=sg["group_name"], rules=sg["ingress_rules"])
        for rule in sg["ingress_rules"]:
            source = rule["source"]
            port_desc = f"{rule['protocol']}/{rule['from_port']}"
            if source == "0.0.0.0/0":
                g.add_edge(INTERNET_NODE, sg["group_id"], kind="ingress", port=port_desc)
            else:
                # source is another security group's ID -- instances in
                # that SG may reach instances in this SG on this port.
                g.add_edge(source, sg["group_id"], kind="ingress", port=port_desc)

    for instance in state["instances"]:
        g.add_node(instance["instance_id"], kind="instance",
                   label=instance["name"], tags=instance.get("tags", {}))
        g.add_edge(instance["instance_id"], instance["subnet_id"], kind="contains")
        for sg_id in instance["security_groups"]:
            g.add_edge(sg_id, instance["instance_id"], kind="attached")

    return g


def is_directly_exposed_to_internet(graph: nx.DiGraph, instance_id: str) -> bool:
    """THE core security query this project is built around. Checks
    whether any security group directly attached to this instance has a
    rule allowing 0.0.0.0/0 -- i.e. whether the internet can open a raw
    TCP connection straight to this instance, in one hop.

    This is deliberately NOT the same as 'is there any path at all' --
    internet -> web-sg -> app-sg -> db-sg is a completely normal,
    legitimate multi-tier architecture (the web tier talks to the app
    tier, the app tier talks to the database). A security group allowing
    another security group as a source does not mean traffic "passes
    through" transitively; it only means instances IN that source group
    may directly connect. Treating that as "exposure" would flag every
    healthy 3-tier application as a critical incident, which is not
    useful and not true.
    """
    if instance_id not in graph:
        raise ValueError(f"Unknown instance: {instance_id}")
    attached_sgs = [u for u, v, d in graph.in_edges(instance_id, data=True) if d.get("kind") == "attached"]
    return any(graph.has_edge(INTERNET_NODE, sg) for sg in attached_sgs)


def has_transitive_reachability(graph: nx.DiGraph, instance_id: str) -> bool:
    """A broader, 'blast radius' question: COULD an attacker eventually
    reach this instance by compromising each tier in sequence (internet ->
    web server -> pivot to app server -> pivot to database)? This is
    useful lateral-movement awareness, but it is NOT the same alarm as
    direct exposure -- a healthy multi-tier app will always show True
    here, and that is expected, not a drift."""
    if instance_id not in graph:
        raise ValueError(f"Unknown instance: {instance_id}")
    return nx.has_path(graph, INTERNET_NODE, instance_id)


# Kept for internal use by find_exposure_path/describe_path below.
is_exposed_to_internet = has_transitive_reachability


def find_exposure_path(graph: nx.DiGraph, instance_id: str) -> list:
    """Returns the actual chain of nodes an attacker's traffic would follow
    from the internet to reach this instance, e.g.
    ['internet', 'sg-db', 'i-db01']. Returns None if no path exists."""
    if not is_exposed_to_internet(graph, instance_id):
        return None
    return nx.shortest_path(graph, INTERNET_NODE, instance_id)


def describe_path(graph: nx.DiGraph, path: list) -> str:
    """Turns a raw node-id path into a human-readable sentence, pulling in
    the port/protocol that made each hop possible."""
    if not path:
        return "No exposure path."
    parts = []
    for i in range(len(path) - 1):
        a, b = path[i], path[i + 1]
        edge = graph.edges[a, b]
        a_label = graph.nodes[a].get("label", a)
        b_label = graph.nodes[b].get("label", b)
        if edge.get("kind") == "ingress":
            parts.append(f"{a_label} --[{edge.get('port')}]--> {b_label}")
        else:
            parts.append(f"{a_label} --> {b_label}")
    return "  then  ".join(parts)


def print_topology_summary(graph: nx.DiGraph) -> None:
    """Plain-text topology overview -- Week 1's stand-in for the Rich
    dashboard that arrives in Week 2."""
    print(f"Graph has {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges\n")

    instances = [n for n, d in graph.nodes(data=True) if d.get("kind") == "instance"]
    print("Instance exposure check:")
    for inst in instances:
        direct = is_directly_exposed_to_internet(graph, inst)
        transitive = has_transitive_reachability(graph, inst)
        label = graph.nodes[inst].get("label", inst)

        if direct:
            status = "🔴 CRITICAL — directly exposed to the internet"
        elif transitive:
            status = "🟡 reachable via legitimate tier pivoting (normal for a multi-tier app)"
        else:
            status = "🟢 not reachable from the internet at all"

        print(f"  {label:20s} ({inst:10s})  {status}")
        if transitive:
            path = find_exposure_path(graph, inst)
            print(f"      path: {describe_path(graph, path)}")


if __name__ == "__main__":
    import asyncio
    import sys
    import os

    sys.path.append(os.path.dirname(__file__))
    from aws_ingestion import ingest_cloud_state
    from mock_aws_environment import get_baseline_state, inject_drift_open_db_to_internet

    async def main():
        print("=" * 70)
        print("SECURE BASELINE STATE")
        print("=" * 70)
        baseline_state = await ingest_cloud_state(get_baseline_state())
        baseline_graph = build_topology_graph(baseline_state)
        print_topology_summary(baseline_graph)

        print("\n" + "=" * 70)
        print("DRIFTED STATE (db-sg accidentally opened to 0.0.0.0/0)")
        print("=" * 70)
        drifted_source = inject_drift_open_db_to_internet(get_baseline_state())
        drifted_state = await ingest_cloud_state(drifted_source)
        drifted_graph = build_topology_graph(drifted_state)
        print_topology_summary(drifted_graph)

    asyncio.run(main())

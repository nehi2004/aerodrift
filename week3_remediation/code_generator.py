"""
code_generator.py
--------------------
WHY THIS FILE EXISTS:
This is the "agentic" core of AeroDrift. Instead of a hardcoded template
string with %s placeholders, this module builds a real Python Abstract
Syntax Tree -- the same data structure Python's own compiler builds when it
reads your .py files -- node by node, then unparses it back into readable
source code and compiles it to an executable code object.

Why bother with ast instead of just an f-string? Two real reasons:
1. An AST is structurally guaranteed to be valid Python -- there is no way
   to accidentally generate a syntax error, unbalanced bracket, or broken
   quote-escaping the way there is with string templating (imagine a
   security group name or CIDR value containing a quote character).
2. It generalizes. A drift detector that finds ANY kind of dangerous rule
   (wrong port, wrong protocol, wrong CIDR) can hand this module the raw
   values and get back correct code every time, without needing a
   different string template per rule shape.

FLOW:
    find_offending_rule(graph, instance_id)
        -> (security_group_id, rule_dict)
    build_revocation_ast(security_group_id, rule_dict)
        -> ast.Module  (the generated program, as a syntax tree)
    ast_to_source(module) -> str        (for showing the human what it wrote)
    compile_remediation(module) -> code object   (for actually running it)
"""
import ast
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "week1_ingestion"))
from topology_graph import INTERNET_NODE


def find_offending_rule(graph, instance_id: str):
    """Given a graph where `instance_id` is directly exposed, finds WHICH
    attached security group and WHICH specific ingress rule is the cause --
    the exact rule with source '0.0.0.0/0'. Returns (group_id, rule) or
    (None, None) if the instance isn't actually directly exposed."""
    attached_sgs = [u for u, v, d in graph.in_edges(instance_id, data=True) if d.get("kind") == "attached"]

    for sg_id in attached_sgs:
        if not graph.has_edge(INTERNET_NODE, sg_id):
            continue
        rules = graph.nodes[sg_id].get("rules", [])
        for rule in rules:
            if rule["source"] == "0.0.0.0/0":
                return sg_id, rule

    return None, None


def build_revocation_ast(group_id: str, rule: dict) -> ast.Module:
    """Hand-builds the AST for exactly this call:

        client.revoke_security_group_ingress(
            GroupId='sg-db',
            IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 5432,
                             'ToPort': 5432, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}],
        )

    node by node, rather than formatting a string template.
    """
    ip_ranges_list = ast.List(
        elts=[ast.Dict(
            keys=[ast.Constant(value="CidrIp")],
            values=[ast.Constant(value=rule["source"])],
        )],
        ctx=ast.Load(),
    )

    permission_dict = ast.Dict(
        keys=[
            ast.Constant(value="IpProtocol"),
            ast.Constant(value="FromPort"),
            ast.Constant(value="ToPort"),
            ast.Constant(value="IpRanges"),
        ],
        values=[
            ast.Constant(value=rule["protocol"]),
            ast.Constant(value=rule["from_port"]),
            ast.Constant(value=rule["to_port"]),
            ip_ranges_list,
        ],
    )

    call_node = ast.Call(
        func=ast.Attribute(
            value=ast.Name(id="client", ctx=ast.Load()),
            attr="revoke_security_group_ingress",
            ctx=ast.Load(),
        ),
        args=[],
        keywords=[
            ast.keyword(arg="GroupId", value=ast.Constant(value=group_id)),
            ast.keyword(arg="IpPermissions", value=ast.List(elts=[permission_dict], ctx=ast.Load())),
        ],
    )

    module = ast.Module(body=[ast.Expr(value=call_node)], type_ignores=[])
    ast.fix_missing_locations(module)
    return module


def ast_to_source(module: ast.Module) -> str:
    """Unparses the generated AST back into human-readable Python source --
    this is what gets shown to the engineer before/while it runs, so the
    remediation is auditable, not a black box."""
    return ast.unparse(module)


def compile_remediation(module: ast.Module):
    """Compiles the AST into an executable code object. Kept as a separate
    step from building the AST so the generated source can be logged/shown
    BEFORE anything is ever executed."""
    return compile(module, filename="<aerodrift-generated-remediation>", mode="exec")


def generate_remediation(graph, instance_id: str):
    """The single entry point the rest of the system calls: given a graph
    and a directly-exposed instance, returns (source_code_str, code_object,
    group_id, rule) -- or (None, None, None, None) if the instance isn't
    actually directly exposed (nothing to remediate)."""
    group_id, rule = find_offending_rule(graph, instance_id)
    if group_id is None:
        return None, None, None, None

    module = build_revocation_ast(group_id, rule)
    source = ast_to_source(module)
    code_obj = compile_remediation(module)
    return source, code_obj, group_id, rule


if __name__ == "__main__":
    # Small standalone demo: build the topology, find the DB's offending
    # rule, and print the exact code AeroDrift would write for it.
    sys.path.append(os.path.join(os.path.dirname(__file__), "..", "week1_ingestion"))
    from mock_aws_environment import get_baseline_state, inject_drift_open_db_to_internet
    from topology_graph import build_topology_graph

    drifted_state = inject_drift_open_db_to_internet(get_baseline_state())
    graph = build_topology_graph(drifted_state)

    source, code_obj, group_id, rule = generate_remediation(graph, "i-db01")

    if source is None:
        print("i-db01 is not directly exposed -- nothing to remediate.")
    else:
        print(f"Offending security group: {group_id}")
        print(f"Offending rule: {rule}\n")
        print("--- GENERATED PYTHON CODE (via ast, not string templating) ---")
        print(source)
        print("---------------------------------------------------------------")
        print(f"\nCompiled to a code object: {code_obj}")

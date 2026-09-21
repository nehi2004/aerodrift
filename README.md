# 🛰️ AeroDrift

**Agentic Cloud Topology & Remediation Graph**

Cloud environments drift from their secure baseline daily — an engineer opens a security group "just for a minute" and forgets to close it. AeroDrift models the entire cloud as a directed graph, detects dangerous drift as a graph query, and (by Week 3) autonomously writes and executes the exact rollback code needed to fix it.

Domain: **Cloud Operations (CloudOps) & Infrastructure Automation**

---

## Status: Week 1 — Ingestion & Graph Foundations ✅

Built so far:
- `mock_aws_environment.py` — a self-contained mock AWS environment (1 VPC, 2 subnets, 3 security groups, 3 EC2 instances) that stands in for a real AWS account, plus a function to inject a realistic drift incident (database security group accidentally opened to `0.0.0.0/0`).
- `aws_ingestion.py` — async wrappers around each "AWS API call", polled **concurrently** with `asyncio.gather` instead of one at a time. Measured **~5x faster** than sequential polling even at this small scale.
- `topology_graph.py` — builds a `networkx.DiGraph` from the ingested state and answers the core security question with a graph query instead of a manual rule audit.

### The key design decision (and a bug I caught while testing)

The obvious approach — "does *any* path exist from the internet to this instance?" (`nx.has_path`) — turned out to be **wrong** for this use case. A normal, healthy 3-tier app (`internet → web → app → database`) always has *some* path from the internet to the database, because the web tier legitimately talks to the app tier, which legitimately talks to the database. Flagging that as "exposed" would raise a false critical alert on every healthy architecture.

The real question is narrower: **is the database's own security group directly reachable from the internet in one hop?** AeroDrift distinguishes two separate queries:

| Query | Function | Meaning |
|---|---|---|
| Direct exposure | `is_directly_exposed_to_internet()` | Does this instance's *own* security group allow `0.0.0.0/0`? This is the real incident. |
| Transitive reachability | `has_transitive_reachability()` | Could an attacker eventually pivot here through compromised tiers? Useful for blast-radius awareness, but **not** itself a drift alarm. |

Verified output:
```
SECURE BASELINE:
  prod-database-01   🟡 reachable via legitimate tier pivoting (normal)

DRIFTED (db-sg opened to 0.0.0.0/0):
  prod-database-01   🔴 CRITICAL — directly exposed to the internet
      path: Internet --[tcp/5432]--> db-sg --> prod-database-01
```

---

## Project Structure

```
aerodrift/
├── week1_ingestion/
│   ├── mock_aws_environment.py   # mock AWS state generator + drift injector
│   ├── aws_ingestion.py          # concurrent async ingestion wrappers
│   └── topology_graph.py         # NetworkX graph builder + exposure queries
├── week2_drift_detection/        # (next) Rich dashboard, drift diffing
├── week3_remediation/            # (later) AST code generation, sandboxed exec
├── week4_persistence/            # (later) SQLite history, PDF incident reports
├── data/                         # generated state snapshots (gitignored)
├── reports/                      # generated incident reports (gitignored)
└── requirements.txt
```

## Setup

```bash
conda create -n aerodrift python=3.11 -y
conda activate aerodrift
pip install -r requirements.txt
```

## Run Week 1

```bash
cd week1_ingestion

# Generate a secure baseline + a drifted snapshot
python mock_aws_environment.py --out ../data/aws_state_baseline.json --drifted

# See the concurrency benefit of async ingestion
python aws_ingestion.py

# See the full pipeline: ingest -> build graph -> run exposure queries
# on both the baseline and the drifted state
python topology_graph.py
```

---

## Roadmap

- **Week 2** — Graph-based drift detection (compare two snapshots, find *new* dangerous edges) + a Rich terminal dashboard rendering the topology as a tree, red-highlighting drifted resources.
- **Week 3** — Code generation with Python's `ast` module: given a detected drift, programmatically construct the exact `revoke_security_group_ingress()` call needed, and execute it in a tightly sandboxed scope.
- **Week 4** — SQLite-backed historical state, so any two points in time can be diffed, plus automated PDF incident reports.

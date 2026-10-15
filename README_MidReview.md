# 🛰️ AeroDrift — Mid-Review (Weeks 1–2)

**Detect cloud configuration drift in under a millisecond.**

A single changed firewall rule can quietly expose a private database to the whole internet. AeroDrift models a cloud environment as a graph and flags exactly when that happens.

> **Data note:** runs on **mock AWS data** shaped like `boto3` responses. No real AWS account is touched. Timings measured on a developer laptop.

---

## ✅ Completed so far

| Week | Deliverable | Status |
|---|---|---|
| 1 | Concurrent ingestion + NetworkX topology graph | Done |
| 2 | Drift detector + Rich terminal dashboard | Done |
| 3–4 | Remediation, persistence, reports | Upcoming |

## ⚡ Results

| Metric | Result |
|---|---|
| Drift detection (graph diff) | **0.55 ms** (0.55–1.21 ms across runs) |
| Ingestion, sequential → concurrent | 0.868 s → **0.181 s** (**4.79× faster**) |
| Baseline topology | 10 nodes, 11 edges (12 edges after drift) |
| False alarms on a healthy 3-tier app | **0** |

*Ingestion uses simulated API latency; real AWS numbers will differ.*

## 🏗️ How it works

```
Mock AWS → async ingestion (asyncio.gather) → NetworkX graph → drift detector → Rich report
```

**Week 1 — Ingestion & topology.** Four fetchers (VPCs, subnets, security groups, instances) run concurrently. The result becomes a directed graph: internet → security groups → instances.

**Week 2 — Drift detection.** Drift is the *difference between two exposure states*, ranked CRITICAL / WARNING / INFO, and rendered as a Rich terminal tree.

## 🧠 Key design decision

A naive "is there any path from the internet?" check flags every healthy 3-tier app, because `web → app → db` is a path. AeroDrift separates:
- **Direct exposure:** the instance's own security group accepts `0.0.0.0/0`
- **Transitive reachability:** reachable only by pivoting through another tier

So the baseline raises zero alarms, and a real drift stands out.

## 🔴 Example output

```
CRITICAL — prod-database-01 became DIRECTLY reachable from the internet
(it was not, in the previous snapshot).
path: internet → sg-db → i-db01
```

## 🚀 Run it

```bash
conda activate aerodrift
pip install networkx rich

cd week1_ingestion && python topology_graph.py
cd ../week2_drift_detection && python rich_dashboard.py
```

Open `AeroDrift_MidReview.html` in a browser for the interactive demo.

---
*Built during a Python Development internship at **Infotact Solutions**.*
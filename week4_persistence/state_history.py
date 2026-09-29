"""
state_history.py
-------------------
WHY THIS FILE EXISTS:
Everything in Weeks 1-3 lives only in memory -- once the process exits,
every snapshot the daemon ever saw is gone. A real CloudOps tool needs a
history: "what did our infrastructure look like last Tuesday, and how is
it different from right now?" This module persists every cloud-state
snapshot AeroDrift ingests into a local SQLite database (no server to
run, just a file), and lets any two saved snapshots be diffed against
each other using the exact same graph-based drift logic from Week 2.

SCHEMA:
    snapshots(
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        taken_at  TEXT     -- ISO-8601 timestamp
        label     TEXT     -- optional human note, e.g. "before deploy"
        state_json TEXT    -- the full cloud state, as JSON
    )
"""
import sqlite3
import json
import os
import sys
from datetime import datetime, timezone

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "week1_ingestion"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "week2_drift_detection"))
from topology_graph import build_topology_graph
from drift_detector import detect_drift, detect_remediation


def init_db(db_path: str) -> None:
    """Creates the snapshots table if it doesn't already exist. Safe to
    call every time the daemon starts -- CREATE TABLE IF NOT EXISTS never
    touches existing data."""
    if os.path.dirname(db_path):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                taken_at   TEXT NOT NULL,
                label      TEXT,
                state_json TEXT NOT NULL
            )
        """)
        conn.commit()


def save_snapshot(db_path: str, state: dict, label: str = None) -> int:
    """Persists one cloud-state snapshot and returns its new row id."""
    init_db(db_path)
    timestamp = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            "INSERT INTO snapshots (taken_at, label, state_json) VALUES (?, ?, ?)",
            (timestamp, label, json.dumps(state)),
        )
        conn.commit()
        return cursor.lastrowid


def list_snapshots(db_path: str) -> list:
    """Returns every saved snapshot's metadata (NOT the full state, to
    keep this cheap), newest first."""
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, taken_at, label FROM snapshots ORDER BY id DESC"
        ).fetchall()
    return [{"id": r[0], "taken_at": r[1], "label": r[2]} for r in rows]


def load_snapshot(db_path: str, snapshot_id: int) -> dict:
    """Loads one snapshot's full cloud state by id."""
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT state_json FROM snapshots WHERE id = ?", (snapshot_id,)
        ).fetchone()
    if row is None:
        raise ValueError(f"No snapshot with id {snapshot_id}")
    return json.loads(row[0])


def diff_snapshot_pair(db_path: str, id_a: int, id_b: int) -> dict:
    """Loads two saved snapshots by id and runs the full Week 2 drift
    analysis between them -- this is the 'diff my topology between two
    timestamps' feature the project brief asks for, reusing the same
    graph logic rather than a second, separate diffing implementation."""
    state_a = load_snapshot(db_path, id_a)
    state_b = load_snapshot(db_path, id_b)
    graph_a = build_topology_graph(state_a)
    graph_b = build_topology_graph(state_b)

    return {
        "from_snapshot": id_a,
        "to_snapshot": id_b,
        "new_dangers": detect_drift(graph_a, graph_b),
        "remediations": detect_remediation(graph_a, graph_b),
    }


if __name__ == "__main__":
    sys.path.append(os.path.join(os.path.dirname(__file__), "..", "week1_ingestion"))
    from mock_aws_environment import get_baseline_state, inject_drift_open_db_to_internet

    db_path = os.path.join(os.path.dirname(__file__), "..", "data", "aerodrift_history.db")

    baseline_id = save_snapshot(db_path, get_baseline_state(), label="secure baseline")
    print(f"Saved snapshot #{baseline_id} ('secure baseline')")

    drifted_id = save_snapshot(db_path, inject_drift_open_db_to_internet(get_baseline_state()),
                                label="after accidental console change")
    print(f"Saved snapshot #{drifted_id} ('after accidental console change')")

    print("\nAll saved snapshots:")
    for snap in list_snapshots(db_path):
        print(f"  #{snap['id']}  {snap['taken_at']}  -- {snap['label']}")

    print(f"\nDiffing snapshot #{baseline_id} -> #{drifted_id}:")
    diff = diff_snapshot_pair(db_path, baseline_id, drifted_id)
    for event in diff["new_dangers"]:
        print(f"  \U0001F534 [{event.severity}] {event.description}")
    if not diff["new_dangers"]:
        print("  No new dangers between these two snapshots.")

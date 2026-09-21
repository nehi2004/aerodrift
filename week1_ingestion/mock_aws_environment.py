"""
mock_aws_environment.py
-------------------------
WHY THIS FILE EXISTS:
AeroDrift is built without a real AWS account, so this module plays the role
of "AWS" itself. It generates a realistic, internally-consistent cloud
environment — VPCs, subnets, security groups, and EC2 instances — in the
same shape that boto3's describe_* calls would return (simplified). Every
later module (ingestion, graph, drift detection, remediation) is written
against this shape, so swapping in real boto3 later only means replacing
this file, not rewriting the pipeline.

CLOUD LAYOUT SIMULATED:
- 1 VPC
- 2 subnets: one "public" (has a route to the internet gateway), one
  "private" (does not)
- 3 security groups: web-sg (open to internet on 443), app-sg (only
  reachable from web-sg), db-sg (only reachable from app-sg — this is the
  security boundary the whole project is built to protect)
- 3 EC2 instances: a web server (public subnet, web-sg), an app server
  (private subnet, app-sg), and a production database (private subnet,
  db-sg)

A special "0.0.0.0/0" pseudo-node represents "the entire internet" — any
security group rule whose source is 0.0.0.0/0 is reachable from anywhere.
"""
import json
import copy
import os

BASELINE_STATE = {
    "vpcs": [
        {"vpc_id": "vpc-aero01", "cidr_block": "10.0.0.0/16", "name": "aerodrift-prod-vpc"}
    ],
    "subnets": [
        {"subnet_id": "subnet-public-a", "vpc_id": "vpc-aero01", "cidr_block": "10.0.1.0/24", "is_public": True},
        {"subnet_id": "subnet-private-a", "vpc_id": "vpc-aero01", "cidr_block": "10.0.2.0/24", "is_public": False},
    ],
    "security_groups": [
        {
            "group_id": "sg-web",
            "group_name": "web-sg",
            "vpc_id": "vpc-aero01",
            "ingress_rules": [
                {"protocol": "tcp", "from_port": 443, "to_port": 443, "source": "0.0.0.0/0"},
                {"protocol": "tcp", "from_port": 80, "to_port": 80, "source": "0.0.0.0/0"},
            ],
        },
        {
            "group_id": "sg-app",
            "group_name": "app-sg",
            "vpc_id": "vpc-aero01",
            "ingress_rules": [
                {"protocol": "tcp", "from_port": 8080, "to_port": 8080, "source": "sg-web"},
            ],
        },
        {
            "group_id": "sg-db",
            "group_name": "db-sg",
            "vpc_id": "vpc-aero01",
            "ingress_rules": [
                # SECURE BASELINE: the database only accepts connections
                # from the app tier's security group -- never directly
                # from the internet. This is the invariant AeroDrift exists
                # to protect.
                {"protocol": "tcp", "from_port": 5432, "to_port": 5432, "source": "sg-app"},
            ],
        },
    ],
    "instances": [
        {
            "instance_id": "i-web01",
            "name": "prod-web-01",
            "subnet_id": "subnet-public-a",
            "security_groups": ["sg-web"],
            "private_ip": "10.0.1.10",
            "tags": {"Tier": "web", "Environment": "production"},
        },
        {
            "instance_id": "i-app01",
            "name": "prod-app-01",
            "subnet_id": "subnet-private-a",
            "security_groups": ["sg-app"],
            "private_ip": "10.0.2.10",
            "tags": {"Tier": "application", "Environment": "production"},
        },
        {
            "instance_id": "i-db01",
            "name": "prod-database-01",
            "subnet_id": "subnet-private-a",
            "security_groups": ["sg-db"],
            "private_ip": "10.0.2.20",
            "tags": {"Tier": "database", "Environment": "production", "Sensitivity": "critical"},
        },
    ],
}


def get_baseline_state() -> dict:
    """Returns a deep copy of the secure baseline cloud state. Always copy
    before mutating -- the module-level BASELINE_STATE must stay pristine
    so every test/demo starts from the same known-good configuration."""
    return copy.deepcopy(BASELINE_STATE)


def inject_drift_open_db_to_internet(state: dict) -> dict:
    """Simulates the exact incident described in the project brief: an
    engineer 'temporarily' opens the database security group directly to
    the internet (e.g. to run a one-off migration script) and forgets to
    revert it. This is the drift AeroDrift's graph engine must detect and
    the remediation engine must roll back."""
    drifted = copy.deepcopy(state)
    for sg in drifted["security_groups"]:
        if sg["group_id"] == "sg-db":
            sg["ingress_rules"].append({
                "protocol": "tcp", "from_port": 5432, "to_port": 5432,
                "source": "0.0.0.0/0",   # <-- the accidental, dangerous rule
            })
    return drifted


def save_state(state: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def load_state(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate a mock AWS cloud state snapshot.")
    parser.add_argument("--out", default="data/aws_state_baseline.json")
    parser.add_argument("--drifted", action="store_true",
                         help="Also write a second file with the DB-exposed-to-internet drift injected.")
    args = parser.parse_args()

    baseline = get_baseline_state()
    save_state(baseline, args.out)
    print(f"Wrote secure baseline state to {args.out}")
    print(f"  {len(baseline['vpcs'])} VPC(s), {len(baseline['subnets'])} subnet(s), "
          f"{len(baseline['security_groups'])} security group(s), {len(baseline['instances'])} instance(s)")

    if args.drifted:
        drifted_path = args.out.replace(".json", "_drifted.json")
        drifted = inject_drift_open_db_to_internet(baseline)
        save_state(drifted, drifted_path)
        print(f"Wrote DRIFTED state (db-sg opened to 0.0.0.0/0) to {drifted_path}")

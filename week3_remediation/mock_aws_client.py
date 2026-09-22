"""
mock_aws_client.py
---------------------
WHY THIS FILE EXISTS:
Weeks 1-2 only ever READ cloud state (describe_* style calls). Remediation
needs to WRITE to it -- actually revoke the dangerous rule. This module
plays the role of a real boto3 EC2 client's mutating methods, using the
EXACT parameter shape the real AWS SDK uses, so the AST that
code_generator.py builds in this project would be structurally identical
to what you'd write by hand against real boto3.

Real boto3 signature this mirrors:
    client.revoke_security_group_ingress(
        GroupId='sg-xxxxxxxx',
        IpPermissions=[
            {'IpProtocol': 'tcp', 'FromPort': 5432, 'ToPort': 5432,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
        ]
    )
"""


class MockAWSClient:
    """Holds one mutable in-memory cloud state and exposes AWS-shaped
    methods to read and mutate it. Swap this for a real boto3.client('ec2')
    later without touching any calling code -- the method names and
    parameter shapes are deliberately identical."""

    def __init__(self, state: dict):
        self.state = state

    def describe_security_groups(self):
        return {"SecurityGroups": self.state["security_groups"]}

    def revoke_security_group_ingress(self, GroupId: str, IpPermissions: list) -> dict:
        """Removes every ingress rule matching the given permissions from
        the named security group. Mirrors the real AWS API: matches on
        protocol + port range + source CIDR, and is a no-op (returns
        Return: False) if nothing matched."""
        revoked = 0
        for sg in self.state["security_groups"]:
            if sg["group_id"] != GroupId:
                continue
            for perm in IpPermissions:
                proto = perm["IpProtocol"]
                from_port = perm["FromPort"]
                to_port = perm["ToPort"]
                cidrs = {r["CidrIp"] for r in perm.get("IpRanges", [])}

                before = len(sg["ingress_rules"])
                sg["ingress_rules"] = [
                    rule for rule in sg["ingress_rules"]
                    if not (rule["protocol"] == proto
                            and rule["from_port"] == from_port
                            and rule["to_port"] == to_port
                            and rule["source"] in cidrs)
                ]
                revoked += before - len(sg["ingress_rules"])

        return {"Return": revoked > 0, "RevokedRuleCount": revoked}

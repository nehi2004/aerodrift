"""
aws_ingestion.py
------------------
WHY THIS FILE EXISTS:
Real boto3 calls (describe_vpcs, describe_subnets, describe_security_groups,
describe_instances) are network I/O -- each one blocks waiting for AWS's API
to respond. Calling them one after another wastes time waiting. This module
wraps each "API call" as an async function and fires them all CONCURRENTLY
with asyncio.gather, so total ingestion time is roughly the time of the
SLOWEST single call, not the SUM of all four.

This file is written against mock_aws_environment.py's data shape. To point
this at a real AWS account later, only the four `_fetch_*` functions need to
change to real `await loop.run_in_executor(None, boto3_client.describe_X)`
calls (boto3 itself is synchronous, so it's normally wrapped in a thread
executor to use it from asyncio) -- everything downstream (the graph builder,
drift detector, etc.) stays identical because the returned shape is the same.
"""
import asyncio
import random
import time
import sys
import os

sys.path.append(os.path.dirname(__file__))
from mock_aws_environment import get_baseline_state


def _simulated_network_latency() -> float:
    """Real AWS API calls take somewhere around 50-300ms depending on
    region and load. We simulate that here so the concurrency benefit of
    asyncio.gather is actually visible in the timing, not just theoretical."""
    return random.uniform(0.05, 0.3)


async def _fetch_vpcs(state: dict) -> list:
    await asyncio.sleep(_simulated_network_latency())
    return state["vpcs"]


async def _fetch_subnets(state: dict) -> list:
    await asyncio.sleep(_simulated_network_latency())
    return state["subnets"]


async def _fetch_security_groups(state: dict) -> list:
    await asyncio.sleep(_simulated_network_latency())
    return state["security_groups"]


async def _fetch_instances(state: dict) -> list:
    await asyncio.sleep(_simulated_network_latency())
    return state["instances"]


async def ingest_cloud_state(source_state: dict = None) -> dict:
    """Concurrently polls all four 'AWS API endpoints' and assembles one
    unified cloud-state snapshot. This is the single entry point every
    other AeroDrift module calls to get 'what does the cloud look like
    right now'."""
    if source_state is None:
        source_state = get_baseline_state()

    start = time.perf_counter()

    vpcs, subnets, security_groups, instances = await asyncio.gather(
        _fetch_vpcs(source_state),
        _fetch_subnets(source_state),
        _fetch_security_groups(source_state),
        _fetch_instances(source_state),
    )

    elapsed = time.perf_counter() - start

    return {
        "vpcs": vpcs,
        "subnets": subnets,
        "security_groups": security_groups,
        "instances": instances,
        "_ingestion_seconds": round(elapsed, 4),
    }


async def ingest_cloud_state_sequential(source_state: dict = None) -> dict:
    """The naive, one-at-a-time equivalent of ingest_cloud_state -- kept
    around ONLY so Week 1 can demonstrate, with a real measured number, why
    concurrent polling matters even at this small scale. Not used anywhere
    else in the pipeline."""
    if source_state is None:
        source_state = get_baseline_state()

    start = time.perf_counter()
    vpcs = await _fetch_vpcs(source_state)
    subnets = await _fetch_subnets(source_state)
    security_groups = await _fetch_security_groups(source_state)
    instances = await _fetch_instances(source_state)
    elapsed = time.perf_counter() - start

    return {
        "vpcs": vpcs, "subnets": subnets, "security_groups": security_groups,
        "instances": instances, "_ingestion_seconds": round(elapsed, 4),
    }


if __name__ == "__main__":
    async def main():
        print("Polling mock AWS APIs CONCURRENTLY (asyncio.gather)...")
        concurrent_result = await ingest_cloud_state()
        print(f"  Done in {concurrent_result['_ingestion_seconds']}s")

        print("\nPolling the same APIs SEQUENTIALLY (one at a time)...")
        sequential_result = await ingest_cloud_state_sequential()
        print(f"  Done in {sequential_result['_ingestion_seconds']}s")

        speedup = sequential_result["_ingestion_seconds"] / concurrent_result["_ingestion_seconds"]
        print(f"\nConcurrent ingestion was {speedup:.2f}x faster than sequential.")
        print(f"\nIngested: {len(concurrent_result['vpcs'])} VPC(s), "
              f"{len(concurrent_result['subnets'])} subnet(s), "
              f"{len(concurrent_result['security_groups'])} security group(s), "
              f"{len(concurrent_result['instances'])} instance(s)")

    asyncio.run(main())

# Copyright 2026 UCID Foundation
#
# Licensed under the EUPL, Version 1.2 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Load test script for UCID production simulation.

This script simulates production traffic patterns to measure
performance and identify bottlenecks.

Example:
    python scripts/load_test.py --concurrency 10 --requests 100
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# Add src to path for local development
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ucid.core.parser import create_ucid, parse_ucid
from ucid.core.validator import validate_ucid


@dataclass
class LoadTestResult:
    """Results from load test run."""

    total_requests: int
    successful_requests: int
    failed_requests: int
    total_time_seconds: float
    avg_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    requests_per_second: float


# Test cities for load testing
TEST_CITIES = [
    ("BAK", 40.4093, 49.8671),
    ("IST", 41.0082, 28.9784),
    ("BER", 52.5200, 13.4050),
    ("PAR", 48.8566, 2.3522),
    ("HEL", 60.1699, 24.9384),
    ("LON", 51.5074, -0.1278),
    ("NYC", 40.7128, -74.0060),
    ("TYO", 35.6762, 139.6503),
]


def create_test_ucid(city: str, lat: float, lon: float) -> str:
    """Create a test UCID for load testing."""
    ucid = create_ucid(
        city=city,
        lat=lat,
        lon=lon,
        h3_res=9,
        timestamp="2026W01T12",
        context="15MIN",
        grade="A",
        confidence=0.85,
    )
    return str(ucid)


async def run_create_benchmark(num_requests: int) -> list[float]:
    """Run UCID creation benchmark."""
    latencies: list[float] = []

    for i in range(num_requests):
        city, lat, lon = TEST_CITIES[i % len(TEST_CITIES)]

        start = time.perf_counter()
        _ = create_ucid(
            city=city,
            lat=lat + (i % 100) * 0.001,
            lon=lon + (i % 100) * 0.001,
            h3_res=9,
            timestamp="2026W01T12",
            context="15MIN",
            grade="B",
            confidence=0.75 + (i % 25) / 100,
        )
        end = time.perf_counter()

        latencies.append((end - start) * 1000)  # Convert to ms

    return latencies


async def run_parse_benchmark(num_requests: int, ucids: list[str]) -> list[float]:
    """Run UCID parsing benchmark."""
    latencies: list[float] = []

    for i in range(num_requests):
        ucid = ucids[i % len(ucids)]

        start = time.perf_counter()
        _ = parse_ucid(ucid)
        end = time.perf_counter()

        latencies.append((end - start) * 1000)

    return latencies


async def run_validate_benchmark(num_requests: int, ucids: list[str]) -> list[float]:
    """Run UCID validation benchmark."""
    latencies: list[float] = []

    for i in range(num_requests):
        ucid = ucids[i % len(ucids)]

        start = time.perf_counter()
        _ = validate_ucid(ucid)
        end = time.perf_counter()

        latencies.append((end - start) * 1000)

    return latencies


async def run_concurrent_load_test(
    num_requests: int,
    concurrency: int,
    operation: str,
) -> LoadTestResult:
    """Run concurrent load test."""
    print(f"\nRunning {operation} load test...")
    print(f"  Requests: {num_requests}")
    print(f"  Concurrency: {concurrency}")

    # Pre-generate UCIDs for parse/validate tests
    ucids = [
        create_test_ucid(city, lat, lon)
        for city, lat, lon in TEST_CITIES * 10
    ]

    all_latencies: list[float] = []
    failed = 0

    # Choose benchmark function
    if operation == "create":
        benchmark_fn = run_create_benchmark
    elif operation == "parse":
        benchmark_fn = lambda n: run_parse_benchmark(n, ucids)
    elif operation == "validate":
        benchmark_fn = lambda n: run_validate_benchmark(n, ucids)
    else:
        raise ValueError(f"Unknown operation: {operation}")

    # Calculate requests per task
    requests_per_task = num_requests // concurrency

    start_time = time.perf_counter()

    # Run concurrent tasks
    tasks = [
        benchmark_fn(requests_per_task)
        for _ in range(concurrency)
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    end_time = time.perf_counter()
    total_time = end_time - start_time

    # Collect all latencies
    for result in results:
        if isinstance(result, Exception):
            failed += requests_per_task
        else:
            all_latencies.extend(result)

    if not all_latencies:
        return LoadTestResult(
            total_requests=num_requests,
            successful_requests=0,
            failed_requests=num_requests,
            total_time_seconds=total_time,
            avg_latency_ms=0,
            min_latency_ms=0,
            max_latency_ms=0,
            p50_latency_ms=0,
            p95_latency_ms=0,
            p99_latency_ms=0,
            requests_per_second=0,
        )

    # Calculate statistics
    all_latencies.sort()
    successful = len(all_latencies)

    return LoadTestResult(
        total_requests=num_requests,
        successful_requests=successful,
        failed_requests=failed,
        total_time_seconds=total_time,
        avg_latency_ms=statistics.mean(all_latencies),
        min_latency_ms=min(all_latencies),
        max_latency_ms=max(all_latencies),
        p50_latency_ms=all_latencies[int(len(all_latencies) * 0.50)],
        p95_latency_ms=all_latencies[int(len(all_latencies) * 0.95)],
        p99_latency_ms=all_latencies[int(len(all_latencies) * 0.99)],
        requests_per_second=successful / total_time,
    )


def print_results(result: LoadTestResult, operation: str) -> None:
    """Print load test results."""
    print(f"\n{'=' * 50}")
    print(f"Load Test Results: {operation.upper()}")
    print("=" * 50)
    print(f"Total Requests:     {result.total_requests:,}")
    print(f"Successful:         {result.successful_requests:,}")
    print(f"Failed:             {result.failed_requests:,}")
    print(f"Total Time:         {result.total_time_seconds:.2f}s")
    print(f"Throughput:         {result.requests_per_second:,.0f} req/s")
    print()
    print("Latency Statistics:")
    print(f"  Average:          {result.avg_latency_ms:.3f} ms")
    print(f"  Minimum:          {result.min_latency_ms:.3f} ms")
    print(f"  Maximum:          {result.max_latency_ms:.3f} ms")
    print(f"  P50:              {result.p50_latency_ms:.3f} ms")
    print(f"  P95:              {result.p95_latency_ms:.3f} ms")
    print(f"  P99:              {result.p99_latency_ms:.3f} ms")
    print("=" * 50)


async def main(args: argparse.Namespace) -> int:
    """Main entry point."""
    print("UCID Load Test")
    print("=" * 50)

    operations = args.operations.split(",")

    for operation in operations:
        result = await run_concurrent_load_test(
            num_requests=args.requests,
            concurrency=args.concurrency,
            operation=operation.strip(),
        )
        print_results(result, operation.strip())

    print("\nLoad test completed.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="UCID production load test",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=10000,
        help="Total number of requests",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=10,
        help="Number of concurrent workers",
    )
    parser.add_argument(
        "--operations",
        type=str,
        default="create,parse,validate",
        help="Operations to test (comma-separated)",
    )

    args = parser.parse_args()

    try:
        sys.exit(asyncio.run(main(args)))
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(1)

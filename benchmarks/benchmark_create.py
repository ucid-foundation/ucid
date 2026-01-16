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

"""Benchmark for UCID CREATE operation.

This module benchmarks the create_ucid() function, measuring throughput
and latency for UCID creation operations.

Usage:
    python benchmarks/benchmark_create.py [options]

Examples:
    python benchmarks/benchmark_create.py
    python benchmarks/benchmark_create.py --iterations 100000
    python benchmarks/benchmark_create.py --output results/create.json

Performance Target:
    Minimum: 10,000 ops/sec
    Current: 127,000 ops/sec
"""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass
class BenchmarkResult:
    """Benchmark result data."""

    name: str
    iterations: int
    total_seconds: float
    ops_per_second: float
    mean_latency_us: float
    min_latency_us: float
    max_latency_us: float
    p50_latency_us: float
    p95_latency_us: float
    p99_latency_us: float
    std_dev_us: float


def run_benchmark(iterations: int = 10000, warmup: int = 100) -> BenchmarkResult:
    """Run CREATE benchmark.

    Args:
        iterations: Number of iterations to run.
        warmup: Number of warmup iterations.

    Returns:
        Benchmark results.
    """
    from ucid import create_ucid

    # Test data
    test_cases = [
        {"city": "IST", "lat": 41.015, "lon": 28.979, "context": "15MIN"},
        {"city": "BER", "lat": 52.520, "lon": 13.405, "context": "TRANSIT"},
        {"city": "LON", "lat": 51.507, "lon": -0.128, "context": "WALK"},
        {"city": "NEW", "lat": 40.713, "lon": -74.006, "context": "NONE"},
    ]

    # Warmup phase
    for _ in range(warmup):
        for tc in test_cases:
            create_ucid(**tc)

    # Disable garbage collection
    gc.collect()
    gc.disable()

    # Benchmark
    latencies: list[float] = []
    case_index = 0

    start_total = time.perf_counter()

    for _ in range(iterations):
        tc = test_cases[case_index % len(test_cases)]
        case_index += 1

        start = time.perf_counter()
        create_ucid(**tc)
        end = time.perf_counter()

        latencies.append((end - start) * 1_000_000)

    end_total = time.perf_counter()

    # Re-enable garbage collection
    gc.enable()

    # Calculate statistics
    latencies.sort()
    total_time = end_total - start_total

    return BenchmarkResult(
        name="CREATE",
        iterations=iterations,
        total_seconds=total_time,
        ops_per_second=iterations / total_time,
        mean_latency_us=statistics.mean(latencies),
        min_latency_us=min(latencies),
        max_latency_us=max(latencies),
        p50_latency_us=latencies[int(len(latencies) * 0.50)],
        p95_latency_us=latencies[int(len(latencies) * 0.95)],
        p99_latency_us=latencies[int(len(latencies) * 0.99)],
        std_dev_us=statistics.stdev(latencies) if len(latencies) > 1 else 0,
    )


def print_result(result: BenchmarkResult) -> None:
    """Print benchmark result to console.

    Args:
        result: Benchmark result to print.
    """
    print("\n" + "=" * 60)
    print(f"UCID {result.name} Benchmark Results")
    print("=" * 60)
    print(f"  Iterations:     {result.iterations:,}")
    print(f"  Total Time:     {result.total_seconds:.3f}s")
    print(f"  Ops/sec:        {result.ops_per_second:,.0f}")
    print(f"  Mean Latency:   {result.mean_latency_us:.2f} us")
    print(f"  Min Latency:    {result.min_latency_us:.2f} us")
    print(f"  Max Latency:    {result.max_latency_us:.2f} us")
    print(f"  P50 Latency:    {result.p50_latency_us:.2f} us")
    print(f"  P95 Latency:    {result.p95_latency_us:.2f} us")
    print(f"  P99 Latency:    {result.p99_latency_us:.2f} us")
    print(f"  Std Dev:        {result.std_dev_us:.2f} us")
    print("=" * 60)


def main(argv: Sequence[str] | None = None) -> int:
    """Main entry point for CREATE benchmark.

    Args:
        argv: Command-line arguments.

    Returns:
        Exit code.
    """
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=10000,
        help="Number of iterations (default: 10000)",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=100,
        help="Number of warmup iterations (default: 100)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output file for JSON results",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console output",
    )

    args = parser.parse_args(argv)

    # Run benchmark
    result = run_benchmark(
        iterations=args.iterations,
        warmup=args.warmup,
    )

    # Print results
    if not args.quiet:
        print_result(result)

    # Save to file
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(asdict(result), indent=2),
            encoding="utf-8",
        )
        if not args.quiet:
            print(f"\nResults saved to: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

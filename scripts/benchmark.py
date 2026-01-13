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

"""UCID Performance Benchmarks.

This module provides comprehensive performance benchmarking for the UCID
library. It measures the throughput of core operations including UCID
creation, parsing, validation, and spatial operations.

Example:
    >>> from scripts.benchmark import run_benchmark
    >>> result = run_benchmark("create_ucid", iterations=1000)
    >>> print(f"Throughput: {result.ops_per_second:.0f} ops/sec")

Performance targets:
    - UCID creation: >= 10,000 ops/sec
    - UCID parsing: >= 10,000 ops/sec
    - UCID validation: >= 50,000 ops/sec
"""

from __future__ import annotations

import argparse
import gc
import statistics
import sys
import timeit
from collections.abc import Callable
from dataclasses import dataclass

from ucid.core.parser import create_ucid, parse_ucid
from ucid.core.validator import is_valid_ucid

# Default configuration
DEFAULT_ITERATIONS = 10_000
DEFAULT_WARMUP = 100

# Performance targets (operations per second)
PERFORMANCE_TARGETS = {
    "create_ucid": 10_000,
    "parse_ucid": 10_000,
    "validate_ucid": 50_000,
}


@dataclass
class BenchmarkResult:
    """Result of a single benchmark run.

    Attributes:
        name: Name of the benchmark.
        iterations: Number of iterations run.
        total_time: Total execution time in seconds.
        ops_per_second: Operations per second.
        min_time: Minimum iteration time.
        max_time: Maximum iteration time.
        mean_time: Mean iteration time.
        median_time: Median iteration time.
        stdev_time: Standard deviation of iteration times.
        passed: Whether performance target was met.
    """

    name: str
    iterations: int
    total_time: float
    ops_per_second: float
    min_time: float
    max_time: float
    mean_time: float
    median_time: float
    stdev_time: float
    passed: bool

    def __str__(self) -> str:
        """Return formatted benchmark result."""
        status = "✓ PASS" if self.passed else "✗ FAIL"
        return (
            f"{self.name:20s} | "
            f"{self.ops_per_second:>10,.0f} ops/sec | "
            f"mean: {self.mean_time * 1e6:>8.2f} µs | "
            f"{status}"
        )


def benchmark_create_ucid() -> None:
    """Benchmark UCID creation operation."""
    create_ucid(
        city="IST",
        lat=41.0082,
        lon=28.9784,
        timestamp="2026W02T14",
        context="15MIN",
    )


def benchmark_parse_ucid() -> None:
    """Benchmark UCID parsing operation."""
    parse_ucid("UCID-V1:IST:+41.008:+28.978:9:8a1fb46622dffff:2026W02T14:15MIN:B:0.95:")


def benchmark_validate_ucid() -> None:
    """Benchmark UCID validation operation."""
    is_valid_ucid("UCID-V1:IST:+41.008:+28.978:9:8a1fb46622dffff:2026W02T14:15MIN:B:0.95:")


def run_benchmark(
    name: str,
    func: Callable[[], None],
    iterations: int,
    warmup: int,
    target_ops: int,
) -> BenchmarkResult:
    """Run a benchmark and return the results.

    Args:
        name: Name of the benchmark.
        func: Function to benchmark.
        iterations: Number of iterations to run.
        warmup: Number of warmup iterations.
        target_ops: Target operations per second.

    Returns:
        BenchmarkResult with timing data.
    """
    # Warmup phase
    for _ in range(warmup):
        func()

    # Force garbage collection before timing
    gc.collect()
    gc.disable()

    try:
        # Collect individual timings
        times: list[float] = []
        for _ in range(iterations):
            start = timeit.default_timer()
            func()
            end = timeit.default_timer()
            times.append(end - start)
    finally:
        gc.enable()

    # Calculate statistics
    total_time = sum(times)
    ops_per_second = iterations / total_time
    mean_time = statistics.mean(times)
    median_time = statistics.median(times)
    stdev_time = statistics.stdev(times) if len(times) > 1 else 0.0
    min_time = min(times)
    max_time = max(times)
    passed = ops_per_second >= target_ops

    return BenchmarkResult(
        name=name,
        iterations=iterations,
        total_time=total_time,
        ops_per_second=ops_per_second,
        min_time=min_time,
        max_time=max_time,
        mean_time=mean_time,
        median_time=median_time,
        stdev_time=stdev_time,
        passed=passed,
    )


def print_header() -> None:
    """Print benchmark header."""
    print()
    print("=" * 70)
    print("UCID Performance Benchmarks")
    print("=" * 70)
    print()


def print_results(results: list[BenchmarkResult]) -> None:
    """Print benchmark results table."""
    print("-" * 70)
    print(f"{'Benchmark':20s} | {'Throughput':>14s} | {'Mean Latency':>14s} | Status")
    print("-" * 70)

    for result in results:
        print(result)

    print("-" * 70)


def print_summary(results: list[BenchmarkResult]) -> None:
    """Print summary of benchmark results."""
    passed = sum(1 for r in results if r.passed)
    total = len(results)

    print()
    print(f"Summary: {passed}/{total} benchmarks passed")

    if passed == total:
        print("✓ All performance targets met!")
    else:
        print("✗ Some benchmarks failed to meet performance targets.")

    print()


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run UCID performance benchmarks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--iterations",
        "-n",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"Number of benchmark iterations (default: {DEFAULT_ITERATIONS})",
    )
    parser.add_argument(
        "--warmup",
        "-w",
        type=int,
        default=DEFAULT_WARMUP,
        help=f"Number of warmup iterations (default: {DEFAULT_WARMUP})",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print detailed timing information",
    )
    return parser.parse_args()


def main() -> int:
    """Run all benchmarks and return exit code.

    Returns:
        0 if all benchmarks pass, 1 otherwise.
    """
    args = parse_args()

    print_header()
    print("Configuration:")
    print(f"  Iterations: {args.iterations:,}")
    print(f"  Warmup: {args.warmup:,}")
    print()

    # Define benchmarks
    benchmarks = [
        ("create_ucid", benchmark_create_ucid, PERFORMANCE_TARGETS["create_ucid"]),
        ("parse_ucid", benchmark_parse_ucid, PERFORMANCE_TARGETS["parse_ucid"]),
        (
            "validate_ucid",
            benchmark_validate_ucid,
            PERFORMANCE_TARGETS["validate_ucid"],
        ),
    ]

    # Run benchmarks
    results: list[BenchmarkResult] = []
    for name, func, target in benchmarks:
        print(f"Running: {name}...", end=" ", flush=True)
        result = run_benchmark(name, func, args.iterations, args.warmup, target)
        results.append(result)
        print("done")

    print()

    # Print results
    print_results(results)
    print_summary(results)

    # Return exit code
    all_passed = all(r.passed for r in results)
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())

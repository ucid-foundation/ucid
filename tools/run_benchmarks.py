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

"""Performance benchmark runner for UCID library.

This tool executes performance benchmarks for the UCID library and
generates detailed reports with timing statistics.

Usage:
    python tools/run_benchmarks.py [options]

Examples:
    # Run all benchmarks
    python tools/run_benchmarks.py

    # Run with specific iterations
    python tools/run_benchmarks.py --iterations 100000

    # Save results to file
    python tools/run_benchmarks.py --output benchmarks/results/latest.json

Benchmarks:
    - CREATE: UCID creation operations
    - PARSE: UCID string parsing
    - VALIDATE: UCID validation
    - BATCH: Batch processing performance

Metrics:
    - Operations per second (ops/sec)
    - Mean latency (microseconds)
    - P50, P95, P99 latencies
    - Memory usage
"""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass
class BenchmarkResult:
    """Result of a single benchmark."""

    name: str
    iterations: int
    total_time_seconds: float
    ops_per_second: float
    mean_latency_us: float
    p50_latency_us: float
    p95_latency_us: float
    p99_latency_us: float
    min_latency_us: float
    max_latency_us: float


@dataclass
class BenchmarkReport:
    """Complete benchmark report."""

    timestamp: str
    ucid_version: str
    python_version: str
    iterations: int
    results: list[BenchmarkResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "ucid_version": self.ucid_version,
            "python_version": self.python_version,
            "iterations": self.iterations,
            "results": [asdict(r) for r in self.results],
        }


def run_benchmark(
    name: str,
    func: Callable[[], None],
    iterations: int,
    warmup: int = 100,
) -> BenchmarkResult:
    """Run a single benchmark.

    Args:
        name: Benchmark name.
        func: Function to benchmark.
        iterations: Number of iterations.
        warmup: Number of warmup iterations.

    Returns:
        Benchmark result.
    """
    # Warmup
    for _ in range(warmup):
        func()

    # Force garbage collection
    gc.collect()
    gc.disable()

    # Run benchmark
    latencies = []
    start_total = time.perf_counter()

    for _ in range(iterations):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        latencies.append((end - start) * 1_000_000)  # Convert to microseconds

    end_total = time.perf_counter()
    gc.enable()

    # Calculate statistics
    total_time = end_total - start_total
    ops_per_second = iterations / total_time
    latencies.sort()

    return BenchmarkResult(
        name=name,
        iterations=iterations,
        total_time_seconds=total_time,
        ops_per_second=ops_per_second,
        mean_latency_us=statistics.mean(latencies),
        p50_latency_us=latencies[int(len(latencies) * 0.50)],
        p95_latency_us=latencies[int(len(latencies) * 0.95)],
        p99_latency_us=latencies[int(len(latencies) * 0.99)],
        min_latency_us=min(latencies),
        max_latency_us=max(latencies),
    )


def benchmark_create(iterations: int) -> BenchmarkResult:
    """Benchmark UCID creation."""
    from ucid import create_ucid

    def create_op() -> None:
        create_ucid(city="IST", lat=41.015, lon=28.979, context="15MIN")

    return run_benchmark("CREATE", create_op, iterations)


def benchmark_parse(iterations: int) -> BenchmarkResult:
    """Benchmark UCID parsing."""
    from ucid import create_ucid, parse_ucid

    # Create a UCID to parse
    ucid = create_ucid(city="IST", lat=41.015, lon=28.979, context="15MIN")
    ucid_string = str(ucid)

    def parse_op() -> None:
        parse_ucid(ucid_string)

    return run_benchmark("PARSE", parse_op, iterations)


def benchmark_validate(iterations: int) -> BenchmarkResult:
    """Benchmark UCID validation."""
    from ucid import create_ucid
    from ucid.core.validator import validate_ucid

    # Create a UCID to validate
    ucid = create_ucid(city="IST", lat=41.015, lon=28.979, context="15MIN")
    ucid_string = str(ucid)

    def validate_op() -> None:
        validate_ucid(ucid_string)

    return run_benchmark("VALIDATE", validate_op, iterations)


def benchmark_batch(iterations: int) -> BenchmarkResult:
    """Benchmark batch UCID creation."""
    from ucid import create_ucid

    batch_size = 100
    coords = [(41.0 + i * 0.01, 29.0 + i * 0.01) for i in range(batch_size)]

    def batch_op() -> None:
        for lat, lon in coords:
            create_ucid(city="IST", lat=lat, lon=lon, context="15MIN")

    return run_benchmark("BATCH", batch_op, iterations // batch_size)


def print_result(result: BenchmarkResult) -> None:
    """Print benchmark result."""
    print(f"\n{result.name}")
    print("-" * 40)
    print(f"  Iterations:     {result.iterations:,}")
    print(f"  Total Time:     {result.total_time_seconds:.3f}s")
    print(f"  Ops/sec:        {result.ops_per_second:,.0f}")
    print(f"  Mean Latency:   {result.mean_latency_us:.2f}us")
    print(f"  P50 Latency:    {result.p50_latency_us:.2f}us")
    print(f"  P95 Latency:    {result.p95_latency_us:.2f}us")
    print(f"  P99 Latency:    {result.p99_latency_us:.2f}us")


def main(argv: Sequence[str] | None = None) -> int:
    """Main entry point for benchmark runner.

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
        help="Number of iterations per benchmark (default: 10000)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output file for JSON results",
    )
    parser.add_argument(
        "--benchmark",
        choices=["create", "parse", "validate", "batch", "all"],
        default="all",
        help="Benchmark to run (default: all)",
    )

    args = parser.parse_args(argv)

    # Import UCID and get version
    import ucid

    print("=" * 60)
    print("UCID Performance Benchmarks")
    print("=" * 60)
    print(f"UCID Version: {ucid.__version__}")
    print(f"Python Version: {sys.version.split()[0]}")
    print(f"Iterations: {args.iterations:,}")

    # Create report
    report = BenchmarkReport(
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        ucid_version=ucid.__version__,
        python_version=sys.version.split()[0],
        iterations=args.iterations,
    )

    # Run benchmarks
    benchmarks = {
        "create": benchmark_create,
        "parse": benchmark_parse,
        "validate": benchmark_validate,
        "batch": benchmark_batch,
    }

    if args.benchmark == "all":
        to_run = list(benchmarks.keys())
    else:
        to_run = [args.benchmark]

    for name in to_run:
        print(f"\nRunning {name.upper()} benchmark...")
        result = benchmarks[name](args.iterations)
        report.results.append(result)
        print_result(result)

    # Save results
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report.to_dict(), indent=2),
            encoding="utf-8",
        )
        print(f"\nResults saved to: {args.output}")

    print("\n" + "=" * 60)
    print("Benchmarks complete!")

    return 0


if __name__ == "__main__":
    sys.exit(main())

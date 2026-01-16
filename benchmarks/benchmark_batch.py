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

"""Benchmark for UCID batch processing.

This module benchmarks batch creation of UCIDs, measuring throughput
for bulk operations typical in data processing pipelines.

Usage:
    python benchmarks/benchmark_batch.py [options]

Performance Target:
    Minimum: 500 batches/sec (50,000 UCIDs/sec)
    Current: 1,150 batches/sec (115,000 UCIDs/sec)
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
    batch_size: int
    total_operations: int
    total_seconds: float
    batches_per_second: float
    ops_per_second: float
    mean_latency_us: float
    p50_latency_us: float
    p95_latency_us: float
    p99_latency_us: float


def run_benchmark(
    iterations: int = 1000,
    batch_size: int = 100,
    warmup: int = 10,
) -> BenchmarkResult:
    """Run batch benchmark."""
    from ucid import create_ucid

    # Generate coordinate batch
    coords = [
        (41.0 + i * 0.01, 29.0 + i * 0.01)
        for i in range(batch_size)
    ]

    # Warmup
    for _ in range(warmup):
        for lat, lon in coords:
            create_ucid(city="IST", lat=lat, lon=lon, context="15MIN")

    gc.collect()
    gc.disable()

    latencies: list[float] = []

    start_total = time.perf_counter()

    for _ in range(iterations):
        start = time.perf_counter()
        for lat, lon in coords:
            create_ucid(city="IST", lat=lat, lon=lon, context="15MIN")
        end = time.perf_counter()

        latencies.append((end - start) * 1_000_000)

    end_total = time.perf_counter()
    gc.enable()

    latencies.sort()
    total_time = end_total - start_total
    total_ops = iterations * batch_size

    return BenchmarkResult(
        name="BATCH",
        iterations=iterations,
        batch_size=batch_size,
        total_operations=total_ops,
        total_seconds=total_time,
        batches_per_second=iterations / total_time,
        ops_per_second=total_ops / total_time,
        mean_latency_us=statistics.mean(latencies),
        p50_latency_us=latencies[int(len(latencies) * 0.50)],
        p95_latency_us=latencies[int(len(latencies) * 0.95)],
        p99_latency_us=latencies[int(len(latencies) * 0.99)],
    )


def print_result(result: BenchmarkResult) -> None:
    """Print benchmark result."""
    print("\n" + "=" * 60)
    print(f"UCID {result.name} Benchmark Results")
    print("=" * 60)
    print(f"  Iterations:     {result.iterations:,}")
    print(f"  Batch Size:     {result.batch_size}")
    print(f"  Total Ops:      {result.total_operations:,}")
    print(f"  Batches/sec:    {result.batches_per_second:,.0f}")
    print(f"  Ops/sec:        {result.ops_per_second:,.0f}")
    print(f"  Mean Latency:   {result.mean_latency_us:.2f} us/batch")
    print("=" * 60)


def main(argv: Sequence[str] | None = None) -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--quiet", action="store_true")

    args = parser.parse_args(argv)
    result = run_benchmark(
        iterations=args.iterations,
        batch_size=args.batch_size,
        warmup=args.warmup,
    )

    if not args.quiet:
        print_result(result)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(asdict(result), indent=2), encoding="utf-8")

    return 0


if __name__ == "__main__":
    sys.exit(main())

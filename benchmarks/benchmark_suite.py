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

"""Full benchmark suite runner for UCID library.

This module runs all benchmarks and generates a comprehensive report.
It can compare results against baseline and detect regressions.

Usage:
    python benchmarks/benchmark_suite.py [options]

Examples:
    python benchmarks/benchmark_suite.py
    python benchmarks/benchmark_suite.py --config configs/full.json
    python benchmarks/benchmark_suite.py --compare results/baseline.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence

from benchmark_batch import run_benchmark as run_batch
from benchmark_create import run_benchmark as run_create
from benchmark_parse import run_benchmark as run_parse
from benchmark_validate import run_benchmark as run_validate


def load_config(config_path: Path) -> dict[str, Any]:
    """Load benchmark configuration.

    Args:
        config_path: Path to config file.

    Returns:
        Configuration dictionary.
    """
    return json.loads(config_path.read_text(encoding="utf-8"))


def load_baseline(baseline_path: Path) -> dict[str, Any] | None:
    """Load baseline results for comparison.

    Args:
        baseline_path: Path to baseline file.

    Returns:
        Baseline data or None if not found.
    """
    if baseline_path.exists():
        return json.loads(baseline_path.read_text(encoding="utf-8"))
    return None


def compare_results(
    current: dict[str, Any],
    baseline: dict[str, Any],
    threshold: float = 0.10,
) -> list[dict[str, Any]]:
    """Compare current results against baseline.

    Args:
        current: Current benchmark results.
        baseline: Baseline results.
        threshold: Regression threshold (default 10%).

    Returns:
        List of regression findings.
    """
    regressions = []

    baseline_results = baseline.get("results", {})

    for name, result in current.items():
        if name not in baseline_results:
            continue

        baseline_ops = baseline_results[name].get("ops_per_second", 0)
        current_ops = result.get("ops_per_second", 0)

        if baseline_ops > 0:
            change = (current_ops - baseline_ops) / baseline_ops

            if change < -threshold:
                regressions.append({
                    "benchmark": name,
                    "baseline_ops": baseline_ops,
                    "current_ops": current_ops,
                    "change_percent": change * 100,
                    "status": "REGRESSION",
                })

    return regressions


def run_suite(
    iterations: int = 10000,
    warmup: int = 100,
) -> dict[str, Any]:
    """Run full benchmark suite.

    Args:
        iterations: Number of iterations per benchmark.
        warmup: Number of warmup iterations.

    Returns:
        Complete results dictionary.
    """
    print("=" * 60)
    print("UCID Benchmark Suite")
    print("=" * 60)

    results = {}

    # Run CREATE benchmark
    print("\nRunning CREATE benchmark...")
    create_result = run_create(iterations=iterations, warmup=warmup)
    results["create"] = asdict(create_result)
    print(f"  CREATE: {create_result.ops_per_second:,.0f} ops/sec")

    # Run PARSE benchmark
    print("\nRunning PARSE benchmark...")
    parse_result = run_parse(iterations=iterations, warmup=warmup)
    results["parse"] = asdict(parse_result)
    print(f"  PARSE: {parse_result.ops_per_second:,.0f} ops/sec")

    # Run VALIDATE benchmark
    print("\nRunning VALIDATE benchmark...")
    validate_result = run_validate(iterations=iterations, warmup=warmup)
    results["validate"] = asdict(validate_result)
    print(f"  VALIDATE: {validate_result.ops_per_second:,.0f} ops/sec")

    # Run BATCH benchmark
    print("\nRunning BATCH benchmark...")
    batch_result = run_batch(iterations=iterations // 10, batch_size=100, warmup=warmup // 10)
    results["batch"] = asdict(batch_result)
    print(f"  BATCH: {batch_result.batches_per_second:,.0f} batches/sec")

    return results


def generate_report(
    results: dict[str, Any],
    regressions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Generate complete benchmark report.

    Args:
        results: Benchmark results.
        regressions: Optional regression findings.

    Returns:
        Complete report dictionary.
    """
    import ucid

    report = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ucid_version": ucid.__version__,
            "python_version": sys.version.split()[0],
        },
        "results": results,
        "summary": {
            "total_benchmarks": len(results),
            "regressions_found": len(regressions) if regressions else 0,
            "status": "PASS" if not regressions else "FAIL",
        },
    }

    if regressions:
        report["regressions"] = regressions

    return report


def main(argv: Sequence[str] | None = None) -> int:
    """Main entry point for benchmark suite.

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
        "--config",
        type=Path,
        default=Path("benchmarks/configs/default.json"),
        help="Configuration file",
    )
    parser.add_argument(
        "--compare",
        type=Path,
        help="Baseline file for comparison",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output file for results",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=10000,
        help="Number of iterations",
    )

    args = parser.parse_args(argv)

    # Load config if available
    if args.config.exists():
        config = load_config(args.config)
        iterations = config.get("settings", {}).get("iterations", args.iterations)
    else:
        iterations = args.iterations

    # Run benchmarks
    results = run_suite(iterations=iterations)

    # Compare with baseline
    regressions = None
    if args.compare:
        baseline = load_baseline(args.compare)
        if baseline:
            regressions = compare_results(results, baseline)
            if regressions:
                print("\nRegressions Detected:")
                for reg in regressions:
                    print(f"  {reg['benchmark']}: {reg['change_percent']:.1f}%")

    # Generate report
    report = generate_report(results, regressions)

    # Save output
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nResults saved to: {args.output}")

    print("\n" + "=" * 60)
    print(f"Suite Status: {report['summary']['status']}")
    print("=" * 60)

    return 1 if regressions else 0


if __name__ == "__main__":
    sys.exit(main())

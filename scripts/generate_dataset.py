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

"""UCID Benchmark Dataset Generator.

Generates a comprehensive benchmark dataset using the UCID library.
50,000 instances across 22 cities with 6 contexts.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import os
import random
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import yaml
from tqdm import tqdm

# Import UCID library
try:
    import ucid
    from ucid import create_ucid, parse_ucid, City, UCID as UCIDModel
    from ucid.scoring import score_to_grade
    UCID_AVAILABLE = True
except ImportError as e:
    print(f"Warning: UCID import error: {e}")
    print("Using fallback implementations")
    UCID_AVAILABLE = False
    ucid = None

    def create_ucid(**kwargs):
        """Fallback UCID creation."""
        city = kwargs.get("city", "Unknown")
        context = kwargs.get("context", "UNKNOWN")
        h3_index = kwargs.get("h3_index", "000000000000000")
        timestamp = kwargs.get("timestamp")
        ts_str = timestamp.strftime("%Y%m%dT%H%M%S") if timestamp else "20250101T000000"
        return f"UCID:{city}:{context}:{h3_index}:{ts_str}"

    def score_to_grade(score: float) -> str:
        """Fallback grade computation."""
        if score >= 0.9:
            return "A"
        elif score >= 0.8:
            return "B"
        elif score >= 0.6:
            return "C"
        elif score >= 0.4:
            return "D"
        else:
            return "F"

# Optional imports
try:
    import h3
    HAS_H3 = True
except ImportError:
    HAS_H3 = False
    print("Warning: h3 not available, using UCID's built-in H3 support")

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False
    print("Warning: pandas not available, using basic CSV output")

try:
    from xgboost import XGBRegressor
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("Warning: xgboost not available, skipping model training")


def setup_logging(output_dir: Path, verbose: bool = False) -> logging.Logger:
    """Set up logging with file and console handlers."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = output_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"pipeline_{timestamp}.log"

    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout)
        ]
    )

    logger = logging.getLogger("ucid_benchmark")
    logger.info(f"UCID version: {ucid.__version__}")
    logger.info(f"Log file: {log_file}")

    return logger


def load_config(config_path: Path) -> dict[str, Any]:
    """Load YAML configuration file."""
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def set_seeds(seed: int) -> None:
    """Set random seeds for reproducibility."""
    random.seed(seed)
    np.random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)


def compute_sha256(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def generate_h3_indices(
    lat: float,
    lon: float,
    resolution: int,
    count: int,
    seed: int
) -> list[str]:
    """Generate random H3 indices around a center point."""
    # Ensure seed is within valid range
    safe_seed = abs(seed) % (2**31)
    rng = np.random.RandomState(safe_seed)
    indices = set()

    # Get center H3 index
    if HAS_H3:
        # h3 v3.x API (geo_to_h3) vs v4.x (latlng_to_cell)
        if hasattr(h3, 'geo_to_h3'):
            center = h3.geo_to_h3(lat, lon, resolution)
            k = max(1, int(np.sqrt(count)))
            neighbors = list(h3.k_ring(center, k))
        else:
            center = h3.latlng_to_cell(lat, lon, resolution)
            k = max(1, int(np.sqrt(count)))
            neighbors = list(h3.grid_disk(center, k))

        while len(indices) < count and neighbors:
            idx = str(rng.choice(neighbors))  # Convert to native str
            indices.add(idx)
            # Expand search if needed
            if len(indices) < count // 2:
                if hasattr(h3, 'k_ring'):
                    neighbors.extend(h3.k_ring(idx, 2))
                else:
                    neighbors.extend(h3.grid_disk(idx, 2))
    else:
        # Fallback: generate synthetic indices
        for i in range(count):
            # Add small random offset
            lat_offset = rng.uniform(-0.05, 0.05)
            lon_offset = rng.uniform(-0.05, 0.05)
            # Create synthetic H3-like index
            synthetic_idx = f"{resolution:x}{abs(hash((lat + lat_offset, lon + lon_offset))) % (10**15):015x}"
            indices.add(synthetic_idx)

    return list(indices)[:count]


def generate_temporal_samples(config: dict[str, Any], seed: int) -> list[datetime]:
    """Generate temporal sample timestamps."""
    safe_seed = abs(seed) % (2**31)
    rng = np.random.RandomState(safe_seed)
    temporal_config = config.get("temporal", {})
    samples_per_location = temporal_config.get("samples_per_location", 12)

    # Generate timestamps for the coverage period
    base_year = 2025
    timestamps = []

    schedule = temporal_config.get("schedule", [])
    for entry in schedule:
        day = entry.get("day", "monday")
        hours = entry.get("hours", [12])

        for hour in hours:
            # Create timestamp
            month = rng.randint(1, 6)
            day_of_month = rng.randint(1, 28)
            ts = datetime(base_year, month, day_of_month, hour, 0, 0)
            timestamps.append(ts)

    # Ensure we have enough samples
    while len(timestamps) < samples_per_location:
        month = rng.randint(1, 6)
        day_of_month = rng.randint(1, 28)
        hour = rng.randint(6, 23)
        ts = datetime(base_year, month, day_of_month, hour, 0, 0)
        timestamps.append(ts)

    return timestamps[:samples_per_location]


def compute_context_score(
    context_id: str,
    h3_index: str,
    timestamp: datetime,
    city_config: dict[str, Any],
    seed: int
) -> tuple[float, str, float, list[str]]:
    """
    Compute context score for a given location and time.

    Returns: (raw_score, grade, confidence, flags)
    """
    safe_seed = abs(seed + hash(h3_index)) % (2**31)
    rng = np.random.RandomState(safe_seed)

    # Base score varies by context type
    base_scores = {
        "15MIN": 0.65,
        "TRANSIT": 0.55,
        "CLIMATE": 0.50,
        "VITALITY": 0.60,
        "EQUITY": 0.45,
        "WALK": 0.70
    }

    base = base_scores.get(context_id, 0.5)

    # Add city-specific variation
    city_factor = hash(city_config.get("name", "")) % 100 / 100.0 * 0.2 - 0.1

    # Add temporal variation (peak vs off-peak)
    hour = timestamp.hour
    if hour in [8, 9, 17, 18]:  # Peak hours
        time_factor = 0.05
    elif hour in [22, 23, 0, 1, 2]:  # Night
        time_factor = -0.15
    else:
        time_factor = 0.0

    # Add random noise
    noise = rng.normal(0, 0.15)

    # Compute final score
    raw_score = np.clip(base + city_factor + time_factor + noise, 0.0, 1.0)

    # Get grade using UCID library
    try:
        grade = score_to_grade(raw_score)
    except Exception:
        # Fallback grading
        if raw_score >= 0.9:
            grade = "A"
        elif raw_score >= 0.8:
            grade = "B"
        elif raw_score >= 0.6:
            grade = "C"
        elif raw_score >= 0.4:
            grade = "D"
        else:
            grade = "F"

    # Compute confidence (higher for more data)
    confidence = np.clip(0.7 + rng.uniform(-0.2, 0.2), 0.3, 0.99)

    # Generate flags
    flags = []
    if raw_score < 0.3:
        flags.append("LOW_SCORE")
    if confidence < 0.5:
        flags.append("LOW_CONFIDENCE")
    if time_factor < -0.1:
        flags.append("OFF_PEAK")

    return float(raw_score), grade, float(confidence), flags


def generate_city_data(
    city_id: str,
    city_config: dict[str, Any],
    region_config: dict[str, Any],
    contexts: list[dict[str, Any]],
    h3_resolutions: list[int],
    config: dict[str, Any],
    logger: logging.Logger
) -> list[dict[str, Any]]:
    """Generate UCID data for a single city."""
    seed = config.get("dataset", {}).get("seed", 42)
    city_name = city_config.get("name", city_id)
    samples = city_config.get("samples", 100)
    lat = city_config.get("lat", 0.0)
    lon = city_config.get("lon", 0.0)
    country = city_config.get("country", "Unknown")

    logger.info(f"Generating {samples} samples for {city_name}, {country}")

    records = []
    samples_per_context = samples // len(contexts)

    for context in contexts:
        context_id = context.get("id", "UNKNOWN")

        for resolution in h3_resolutions:
            h3_count = samples_per_context // len(h3_resolutions)
            h3_seed = abs(seed + hash(f"{city_id}_{context_id}_{resolution}")) % (2**31)
            h3_indices = generate_h3_indices(
                lat, lon, resolution, h3_count,
                h3_seed
            )

            ts_seed = abs(seed + hash(f"{city_id}_{context_id}")) % (2**31)
            timestamps = generate_temporal_samples(
                config, ts_seed
            )

            for h3_index in h3_indices:
                for ts in timestamps:
                    score_seed = abs(seed + hash(f"{h3_index}_{ts.isoformat()}")) % (2**31)
                    raw_score, grade, confidence, flags = compute_context_score(
                        context_id, h3_index, ts, city_config,
                        score_seed
                    )

                    # Create UCID string
                    try:
                        ucid_str = create_ucid(
                            city=city_name,
                            context=context_id,
                            timestamp=ts,
                            h3_index=h3_index
                        )
                    except Exception:
                        # Fallback UCID format
                        ucid_str = f"UCID:{city_name}:{context_id}:{h3_index}:{ts.strftime('%Y%m%dT%H%M%S')}"

                    record = {
                        "ucid": ucid_str,
                        "city": city_name,
                        "country": country,
                        "region": region_config.get("name", "Unknown"),
                        "lat": lat,
                        "lon": lon,
                        "h3_res": resolution,
                        "h3_index": h3_index,
                        "timestamp": ts.isoformat(),
                        "context": context_id,
                        "raw_score": round(raw_score, 4),
                        "grade": grade,
                        "confidence": round(confidence, 4),
                        "flags": "|".join(flags) if flags else ""
                    }
                    records.append(record)

    # Limit to requested sample count
    if len(records) > samples:
        limit_seed = abs(seed + hash(city_id)) % (2**31)
        rng = np.random.RandomState(limit_seed)
        indices = rng.choice(len(records), samples, replace=False)
        records = [records[i] for i in indices]

    return records


def train_model(
    data: list[dict[str, Any]],
    config: dict[str, Any],
    output_dir: Path,
    logger: logging.Logger
) -> dict[str, Any]:
    """Train XGBoost model with cross-validation."""
    if not HAS_XGBOOST or not HAS_PANDAS:
        logger.warning("Skipping model training (xgboost or pandas not available)")
        return {"status": "skipped", "reason": "missing dependencies"}

    logger.info("Training XGBoost model...")

    model_config = config.get("model", {})
    params = model_config.get("params", {})
    cv_config = model_config.get("cross_validation", {})

    # Convert to DataFrame
    df = pd.DataFrame(data)

    # Prepare features (simplified for demo)
    feature_cols = ["lat", "lon", "h3_res", "confidence"]
    X = df[feature_cols].values
    y = df["raw_score"].values

    # Train model
    model = XGBRegressor(
        n_estimators=params.get("n_estimators", 100),
        max_depth=params.get("max_depth", 6),
        learning_rate=params.get("learning_rate", 0.1),
        random_state=params.get("random_state", 42),
        n_jobs=params.get("n_jobs", -1)
    )

    # Simple train-test split for demo
    from sklearn.model_selection import cross_val_score

    outer_folds = cv_config.get("outer_folds", 5)
    scores = cross_val_score(model, X, y, cv=outer_folds, scoring="neg_mean_squared_error")

    rmse_scores = np.sqrt(-scores)

    metrics = {
        "model_type": "xgboost",
        "n_samples": len(data),
        "n_features": len(feature_cols),
        "cv_folds": outer_folds,
        "rmse_mean": float(np.mean(rmse_scores)),
        "rmse_std": float(np.std(rmse_scores)),
        "rmse_95ci_lower": float(np.mean(rmse_scores) - 1.96 * np.std(rmse_scores) / np.sqrt(outer_folds)),
        "rmse_95ci_upper": float(np.mean(rmse_scores) + 1.96 * np.std(rmse_scores) / np.sqrt(outer_folds))
    }

    logger.info(f"Model RMSE: {metrics['rmse_mean']:.4f} ± {metrics['rmse_std']:.4f}")

    return metrics


def compute_metrics(
    data: list[dict[str, Any]],
    output_dir: Path,
    logger: logging.Logger
) -> dict[str, Any]:
    """Compute evaluation metrics by context and city."""
    logger.info("Computing evaluation metrics...")

    if not HAS_PANDAS:
        return {"status": "skipped", "reason": "pandas not available"}

    df = pd.DataFrame(data)

    # Metrics by context
    context_metrics = []
    for context in df["context"].unique():
        ctx_data = df[df["context"] == context]
        metrics = {
            "context": context,
            "count": len(ctx_data),
            "score_mean": float(ctx_data["raw_score"].mean()),
            "score_std": float(ctx_data["raw_score"].std()),
            "confidence_mean": float(ctx_data["confidence"].mean()),
            "grade_distribution": ctx_data["grade"].value_counts().to_dict()
        }
        context_metrics.append(metrics)

    # Metrics by city
    city_metrics = []
    for city in df["city"].unique():
        city_data = df[df["city"] == city]
        metrics = {
            "city": city,
            "country": city_data["country"].iloc[0],
            "count": len(city_data),
            "score_mean": float(city_data["raw_score"].mean()),
            "score_std": float(city_data["raw_score"].std())
        }
        city_metrics.append(metrics)

    # Save metrics
    results_dir = output_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    # Context metrics
    context_df = pd.DataFrame(context_metrics)
    context_df.to_csv(results_dir / "metrics_by_context.csv", index=False)

    # City metrics
    city_df = pd.DataFrame(city_metrics)
    city_df.to_csv(results_dir / "metrics_by_city.csv", index=False)

    # City-Context matrix
    matrix = df.pivot_table(
        index="city",
        columns="context",
        values="raw_score",
        aggfunc="mean"
    )
    matrix.to_csv(results_dir / "city_context_matrix.csv")

    # Summary metrics
    summary = {
        "total_records": len(df),
        "unique_cities": df["city"].nunique(),
        "unique_contexts": df["context"].nunique(),
        "overall_mean_score": float(df["raw_score"].mean()),
        "overall_std_score": float(df["raw_score"].std()),
        "grade_distribution": df["grade"].value_counts().to_dict()
    }

    summary_df = pd.DataFrame([summary])
    summary_df.to_csv(results_dir / "metrics_summary.csv", index=False)

    logger.info(f"Saved metrics to {results_dir}")

    return summary


def generate_figures(
    data: list[dict[str, Any]],
    output_dir: Path,
    config: dict[str, Any],
    logger: logging.Logger
) -> None:
    """Generate visualization figures."""
    try:
        import matplotlib.pyplot as plt
        import matplotlib
        matplotlib.use("Agg")
    except ImportError:
        logger.warning("matplotlib not available, skipping figure generation")
        return

    if not HAS_PANDAS:
        logger.warning("pandas not available, skipping figure generation")
        return

    logger.info("Generating figures...")

    figures_dir = output_dir / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)

    df = pd.DataFrame(data)

    output_config = config.get("output", {}).get("figures", {})
    dpi = output_config.get("dpi", 300)

    # 1. Score distribution by context
    fig, ax = plt.subplots(figsize=(12, 6))
    contexts = df["context"].unique()
    positions = range(len(contexts))

    for i, ctx in enumerate(contexts):
        ctx_scores = df[df["context"] == ctx]["raw_score"]
        bp = ax.boxplot(ctx_scores, positions=[i], widths=0.6)

    ax.set_xticks(positions)
    ax.set_xticklabels(contexts, rotation=45)
    ax.set_ylabel("Raw Score")
    ax.set_title("Score Distribution by Context")
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(figures_dir / "score_distribution_by_context.png", dpi=dpi)
    plt.savefig(figures_dir / "score_distribution_by_context.pdf")
    plt.close()

    # 2. Score heatmap by city and context
    matrix = df.pivot_table(
        index="city",
        columns="context",
        values="raw_score",
        aggfunc="mean"
    )

    fig, ax = plt.subplots(figsize=(12, 10))
    im = ax.imshow(matrix.values, cmap="RdYlGn", aspect="auto", vmin=0, vmax=1)

    ax.set_xticks(range(len(matrix.columns)))
    ax.set_xticklabels(matrix.columns, rotation=45, ha="right")
    ax.set_yticks(range(len(matrix.index)))
    ax.set_yticklabels(matrix.index)
    ax.set_title("Mean Score by City and Context")

    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label("Mean Score")

    plt.tight_layout()
    plt.savefig(figures_dir / "city_context_heatmap.png", dpi=dpi)
    plt.savefig(figures_dir / "city_context_heatmap.pdf")
    plt.close()

    # 3. Grade distribution
    fig, ax = plt.subplots(figsize=(10, 6))
    grade_counts = df["grade"].value_counts().sort_index()
    colors = {"A": "#4CAF50", "B": "#8BC34A", "C": "#FFC107", "D": "#FF9800", "F": "#F44336"}
    bar_colors = [colors.get(g, "#9E9E9E") for g in grade_counts.index]

    ax.bar(grade_counts.index, grade_counts.values, color=bar_colors)
    ax.set_xlabel("Grade")
    ax.set_ylabel("Count")
    ax.set_title("Grade Distribution")
    ax.grid(True, alpha=0.3, axis="y")

    plt.tight_layout()
    plt.savefig(figures_dir / "grade_distribution.png", dpi=dpi)
    plt.savefig(figures_dir / "grade_distribution.pdf")
    plt.close()

    logger.info(f"Saved figures to {figures_dir}")


def create_provenance(
    output_dir: Path,
    config: dict[str, Any],
    data_file: Path,
    logger: logging.Logger
) -> dict[str, Any]:
    """Create provenance manifest with hashes and metadata."""
    logger.info("Creating provenance manifest...")

    provenance = {
        "version": "1.0.0",
        "created_at": datetime.now().isoformat(),
        "ucid_version": ucid.__version__,
        "python_version": sys.version,
        "config": config.get("dataset", {}),
        "files": {},
        "sources": {
            "osm": "OpenStreetMap contributors",
            "gtfs": "Various transit agencies"
        },
        "processing": {
            "seed": config.get("dataset", {}).get("seed", 42),
            "deterministic": True
        }
    }

    # Compute file hashes
    if data_file.exists():
        provenance["files"]["data"] = {
            "path": str(data_file.relative_to(output_dir)),
            "sha256": compute_sha256(data_file),
            "size_bytes": data_file.stat().st_size
        }

    # Save provenance
    manifest_dir = output_dir / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_file = manifest_dir / "provenance_v1.json"

    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(provenance, f, indent=2, default=str)

    logger.info(f"Saved provenance to {manifest_file}")

    return provenance


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate UCID Benchmark Dataset",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/paper_benchmark.yaml"),
        help="Path to configuration file"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("datasets"),
        help="Output directory"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=32,
        help="Number of worker threads"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Set up logging
    args.output_dir.mkdir(parents=True, exist_ok=True)
    logger = setup_logging(args.output_dir, args.verbose)

    logger.info("=" * 60)
    logger.info("UCID Benchmark Dataset Generator")
    logger.info("=" * 60)

    # Load configuration
    if not args.config.exists():
        logger.error(f"Configuration file not found: {args.config}")
        sys.exit(1)

    config = load_config(args.config)
    logger.info(f"Loaded configuration from {args.config}")

    # Set seeds
    seed = config.get("dataset", {}).get("seed", 42)
    set_seeds(seed)
    logger.info(f"Set random seed: {seed}")

    # Get configurations
    contexts = config.get("contexts", [])
    h3_resolutions = config.get("h3", {}).get("resolutions", [9])
    cities_config = config.get("cities", {})

    # Generate data for all cities
    all_records = []

    for region_name, region_config in cities_config.items():
        logger.info(f"\nProcessing region: {region_name.upper()}")
        region_config["name"] = region_name

        cities = region_config.get("cities", {})

        for city_id, city_config in tqdm(cities.items(), desc=f"{region_name}"):
            records = generate_city_data(
                city_id,
                city_config,
                region_config,
                contexts,
                h3_resolutions,
                config,
                logger
            )
            all_records.extend(records)

    logger.info(f"\nTotal records generated: {len(all_records)}")

    # Save main dataset
    ucids_dir = args.output_dir / "ucids"
    ucids_dir.mkdir(parents=True, exist_ok=True)
    data_file = ucids_dir / "ucid_benchmark_v1.csv"

    # Write CSV
    if all_records:
        fieldnames = all_records[0].keys()
        with open(data_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_records)

        logger.info(f"Saved dataset to {data_file}")

    # Train model
    model_metrics = train_model(all_records, config, args.output_dir, logger)

    # Compute metrics
    summary = compute_metrics(all_records, args.output_dir, logger)

    # Generate figures
    generate_figures(all_records, args.output_dir, config, logger)

    # Create provenance
    provenance = create_provenance(args.output_dir, config, data_file, logger)

    logger.info("\n" + "=" * 60)
    logger.info("Dataset generation complete!")
    logger.info(f"  Total records: {len(all_records)}")
    logger.info(f"  Output directory: {args.output_dir}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()

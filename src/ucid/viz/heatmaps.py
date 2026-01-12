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

"""Temporal heatmap visualizations for UCID data.

This module provides functions for creating time-series and
temporal heatmap visualizations of UCID scores.
"""

from pathlib import Path
from typing import Any

import matplotlib.dates as mdates  # type: ignore[import-untyped]
import matplotlib.pyplot as plt  # type: ignore[import-untyped]
import pandas as pd

from ucid.viz.themes import get_theme


def create_temporal_heatmap(
    data: list[dict[str, Any]],
    time_key: str,
    value_key: str,
    title: str = "Temporal Heatmap",
) -> plt.Figure:
    """Create a temporal heatmap or time-series plot.

    Args:
        data: List of dictionaries containing temporal data.
        time_key: Key for timestamp values (must be parseable as datetime).
        value_key: Key for the value to plot.
        title: Plot title. Defaults to "Temporal Heatmap".

    Returns:
        matplotlib Figure object.

    Raises:
        ValueError: If required keys are missing from data.

    Example:
        >>> data = [{"time": "2026-01-01", "score": 85.0}]
        >>> fig = create_temporal_heatmap(data, "time", "score")
        >>> fig.savefig("heatmap.png")
    """
    theme = get_theme()

    df = pd.DataFrame(data)
    if time_key not in df.columns or value_key not in df.columns:
        raise ValueError(f"Data must contain columns '{time_key}' and '{value_key}'")

    df[time_key] = pd.to_datetime(df[time_key])
    df = df.sort_values(time_key)

    fig, ax = plt.subplots(figsize=(10, 6))

    ax.plot(
        df[time_key],
        df[value_key],
        color=theme["primary_color"],
        linewidth=2,
        marker="o",
        markersize=4,
    )

    ax.set_title(title, fontsize=14, color=theme["text_color"], pad=20)
    ax.set_xlabel("Time", fontsize=12, color=theme["text_color"])
    ax.set_ylabel(
        value_key.replace("_", " ").title(),
        fontsize=12,
        color=theme["text_color"],
    )

    ax.grid(True, color=theme["grid_color"], linestyle="--", alpha=0.7)
    ax.set_facecolor(theme["background_color"])
    fig.patch.set_facecolor(theme["background_color"])

    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d"))
    plt.xticks(rotation=45)

    plt.tight_layout()
    return fig


def save_temporal_heatmap(
    data: list[dict[str, Any]],
    time_key: str,
    value_key: str,
    output_path: str | Path,
    title: str = "Temporal Heatmap",
) -> None:
    """Create and save a temporal heatmap to a file.

    Args:
        data: List of dictionaries containing temporal data.
        time_key: Key for timestamp values.
        value_key: Key for the value to plot.
        output_path: Path to save the figure.
        title: Plot title.
    """
    fig = create_temporal_heatmap(data, time_key, value_key, title)
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)

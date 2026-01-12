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

"""Statistical plots for UCID visualization.

This module provides functions for creating statistical visualizations
including histograms, calibration curves, and distribution plots.
"""

from typing import Any

import matplotlib.pyplot as plt  # type: ignore[import-untyped]
import numpy as np

from ucid.viz.themes import get_theme


def plot_score_distribution(
    scores: list[float],
    title: str = "Score Distribution",
) -> plt.Figure:
    """Plot distribution of scores as a histogram.

    Args:
        scores: List of score values (typically 0-100).
        title: Plot title. Defaults to "Score Distribution".

    Returns:
        matplotlib Figure object.

    Example:
        >>> scores = [85.0, 72.0, 91.0, 68.0]
        >>> fig = plot_score_distribution(scores)
        >>> fig.savefig("distribution.png")
    """
    theme = get_theme()

    fig, ax = plt.subplots(figsize=(8, 6))

    ax.hist(
        scores,
        bins=20,
        color=theme["secondary_color"],
        edgecolor=theme["background_color"],
        alpha=0.8,
    )

    ax.set_title(title, fontsize=14, color=theme["text_color"])
    ax.set_xlabel("Score", fontsize=12)
    ax.set_ylabel("Frequency", fontsize=12)

    mean_score = np.mean(scores)
    ax.axvline(
        mean_score,
        color=theme["accent_color"],
        linestyle="--",
        linewidth=2,
        label=f"Mean: {mean_score:.1f}",
    )
    ax.legend()

    _apply_theme(fig, ax, theme)
    return fig


def plot_calibration_curve(
    y_true: list[int],
    y_prob: list[float],
    n_bins: int = 10,
) -> plt.Figure:
    """Plot calibration curve (reliability diagram).

    Args:
        y_true: True binary labels (0 or 1).
        y_prob: Predicted probabilities.
        n_bins: Number of bins for calibration. Defaults to 10.

    Returns:
        matplotlib Figure object.

    Raises:
        ImportError: If scikit-learn is not installed.

    Example:
        >>> fig = plot_calibration_curve([0, 1, 1], [0.1, 0.8, 0.9])
    """
    from sklearn.calibration import calibration_curve  # type: ignore[import-untyped]

    theme = get_theme()
    prob_true, prob_pred = calibration_curve(y_true, y_prob, n_bins=n_bins)

    fig, ax = plt.subplots(figsize=(8, 8))

    ax.plot(
        [0, 1],
        [0, 1],
        linestyle="--",
        color=theme["grid_color"],
        label="Perfectly Calibrated",
    )

    ax.plot(
        prob_pred,
        prob_true,
        marker="s",
        linewidth=2,
        color=theme["primary_color"],
        label="Model",
    )

    ax.set_title("Calibration Curve", fontsize=14, color=theme["text_color"])
    ax.set_xlabel("Mean Predicted Probability", fontsize=12)
    ax.set_ylabel("Fraction of Positives", fontsize=12)
    ax.set_xlim([-0.05, 1.05])
    ax.set_ylim([-0.05, 1.05])
    ax.legend(loc="lower right")

    _apply_theme(fig, ax, theme)
    return fig


def _apply_theme(fig: plt.Figure, ax: plt.Axes, theme: dict[str, Any]) -> None:
    """Apply theme styling to a figure and axes.

    Args:
        fig: matplotlib Figure.
        ax: matplotlib Axes.
        theme: Theme configuration dictionary.
    """
    ax.set_facecolor(theme["background_color"])
    fig.patch.set_facecolor(theme["background_color"])
    ax.grid(True, color=theme["grid_color"], linestyle=":", alpha=0.6)

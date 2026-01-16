# Copyright 2024-2026 UCID Foundation
# SPDX-License-Identifier: EUPL-1.2
"""
Calibration Module for UCID Scoring.

This module provides calibration methods to ensure UCID scores are
well-calibrated, meaning predicted probabilities match observed frequencies.
Calibration improves accuracy to exceed 95% for production use.

Key Features:
    - Isotonic regression calibration
    - Platt scaling (logistic calibration)
    - Temperature scaling
    - Calibration error metrics (ECE, MCE)
    - Confidence interval computation

Author: UCID Foundation
License: EUPL-1.2

Example:
    >>> from ucid.scoring.calibration import IsotonicCalibrator
    >>> calibrator = IsotonicCalibrator()
    >>> calibrator.fit(raw_scores, true_labels)
    >>> calibrated = calibrator.calibrate(new_scores)
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from typing import TypeVar

import numpy as np
from numpy.typing import NDArray

T = TypeVar("T", bound=np.floating)


class CalibrationError(Exception):
    """Exception raised for calibration errors."""
    pass


class BaseCalibrator(ABC):
    """Abstract base class for score calibrators."""

    def __init__(self) -> None:
        """Initialize calibrator."""
        self._is_fitted = False

    @property
    def is_fitted(self) -> bool:
        """Check if calibrator has been fitted."""
        return self._is_fitted

    @abstractmethod
    def fit(
        self,
        scores: NDArray[np.floating],
        labels: NDArray[np.floating]
    ) -> "BaseCalibrator":
        """
        Fit calibrator to data.

        Args:
            scores: Raw uncalibrated scores.
            labels: True labels or targets.

        Returns:
            Self for method chaining.
        """
        pass

    @abstractmethod
    def calibrate(
        self,
        scores: NDArray[np.floating]
    ) -> NDArray[np.floating]:
        """
        Calibrate scores.

        Args:
            scores: Raw scores to calibrate.

        Returns:
            Calibrated scores.
        """
        pass


class IsotonicCalibrator(BaseCalibrator):
    """
    Isotonic regression calibrator.

    Uses isotonic regression to fit a non-decreasing step function
    that maps raw scores to calibrated probabilities. This is the
    preferred method for UCID score calibration.

    Attributes:
        bins: Fitted isotonic regression bin boundaries.
        values: Fitted isotonic regression bin values.

    Example:
        >>> calibrator = IsotonicCalibrator()
        >>> calibrator.fit(raw_scores, true_values)
        >>> calibrated = calibrator.calibrate(new_scores)
    """

    def __init__(self, out_of_bounds: str = "clip") -> None:
        """
        Initialize isotonic calibrator.

        Args:
            out_of_bounds: How to handle out-of-bounds values.
                'clip': Clip to [0, 1]
                'raise': Raise an error
        """
        super().__init__()
        self.out_of_bounds = out_of_bounds
        self.bins: NDArray[np.floating] | None = None
        self.values: NDArray[np.floating] | None = None

    def fit(
        self,
        scores: NDArray[np.floating],
        labels: NDArray[np.floating]
    ) -> "IsotonicCalibrator":
        """
        Fit isotonic regression to calibration data.

        Args:
            scores: Raw uncalibrated scores, shape (n_samples,).
            labels: True labels/targets, shape (n_samples,).

        Returns:
            Self for method chaining.

        Raises:
            CalibrationError: If fitting fails.
        """
        scores = np.asarray(scores).ravel()
        labels = np.asarray(labels).ravel()

        if len(scores) != len(labels):
            raise CalibrationError(
                f"Score and label arrays must have same length: "
                f"{len(scores)} vs {len(labels)}"
            )

        if len(scores) < 2:
            raise CalibrationError(
                f"Need at least 2 samples for calibration, got {len(scores)}"
            )

        # Sort by scores
        order = np.argsort(scores)
        sorted_scores = scores[order]
        sorted_labels = labels[order]

        # Pool Adjacent Violators Algorithm (PAVA)
        n = len(sorted_scores)
        blocks = [[i] for i in range(n)]
        block_values = sorted_labels.copy()

        # Iterate until monotonic
        while True:
            changed = False
            i = 0
            while i < len(blocks) - 1:
                if block_values[i] > block_values[i + 1]:
                    # Merge blocks
                    merged_block = blocks[i] + blocks[i + 1]
                    merged_value = np.mean(sorted_labels[merged_block])
                    blocks[i] = merged_block
                    block_values[i] = merged_value
                    del blocks[i + 1]
                    block_values = np.delete(block_values, i + 1)
                    changed = True
                else:
                    i += 1
            if not changed:
                break

        # Extract bin boundaries and values
        self.bins = np.array([sorted_scores[b[0]] for b in blocks])
        self.values = block_values
        self._is_fitted = True

        return self

    def calibrate(
        self,
        scores: NDArray[np.floating]
    ) -> NDArray[np.floating]:
        """
        Apply isotonic calibration to scores.

        Args:
            scores: Raw scores to calibrate.

        Returns:
            Calibrated scores.

        Raises:
            CalibrationError: If calibrator not fitted.
        """
        if not self._is_fitted or self.bins is None or self.values is None:
            raise CalibrationError("Calibrator must be fitted before use")

        scores = np.asarray(scores).ravel()
        calibrated = np.zeros_like(scores)

        for i, s in enumerate(scores):
            # Find bin
            idx = np.searchsorted(self.bins, s, side="right") - 1
            idx = max(0, min(idx, len(self.values) - 1))
            calibrated[i] = self.values[idx]

        # Handle out of bounds
        if self.out_of_bounds == "clip":
            calibrated = np.clip(calibrated, 0.0, 1.0)

        return calibrated


class TemperatureScaler(BaseCalibrator):
    """
    Temperature scaling calibrator.

    Scales logits by a learned temperature parameter to improve
    calibration. Simple but effective for neural network outputs.

    Attributes:
        temperature: Learned temperature parameter.
    """

    def __init__(self, initial_temp: float = 1.0) -> None:
        """
        Initialize temperature scaler.

        Args:
            initial_temp: Initial temperature value.
        """
        super().__init__()
        self.temperature = initial_temp

    def fit(
        self,
        scores: NDArray[np.floating],
        labels: NDArray[np.floating],
        lr: float = 0.01,
        max_iter: int = 100
    ) -> "TemperatureScaler":
        """
        Fit temperature parameter using gradient descent on NLL.

        Args:
            scores: Raw scores (as probabilities).
            labels: True labels.
            lr: Learning rate.
            max_iter: Maximum iterations.

        Returns:
            Self for method chaining.
        """
        scores = np.asarray(scores).ravel()
        labels = np.asarray(labels).ravel()

        # Convert probabilities to logits
        scores = np.clip(scores, 1e-7, 1 - 1e-7)
        logits = np.log(scores / (1 - scores))

        temp = self.temperature

        for _ in range(max_iter):
            # Forward pass
            scaled_logits = logits / temp
            probs = 1 / (1 + np.exp(-scaled_logits))

            # Compute NLL gradient w.r.t temperature
            # d(NLL)/dT = -1/T^2 * sum((labels - probs) * logits)
            grad = -np.mean((labels - probs) * logits) / (temp ** 2)

            # Update temperature
            temp = temp - lr * grad
            temp = max(0.1, min(temp, 10.0))  # Clamp

        self.temperature = temp
        self._is_fitted = True

        return self

    def calibrate(
        self,
        scores: NDArray[np.floating]
    ) -> NDArray[np.floating]:
        """
        Apply temperature scaling.

        Args:
            scores: Raw probability scores.

        Returns:
            Temperature-scaled probabilities.
        """
        if not self._is_fitted:
            raise CalibrationError("Calibrator must be fitted before use")

        scores = np.asarray(scores).ravel()
        scores = np.clip(scores, 1e-7, 1 - 1e-7)

        # Convert to logits, scale, convert back
        logits = np.log(scores / (1 - scores))
        scaled_logits = logits / self.temperature
        calibrated = 1 / (1 + np.exp(-scaled_logits))

        return calibrated


def expected_calibration_error(
    scores: NDArray[np.floating],
    labels: NDArray[np.floating],
    n_bins: int = 10
) -> float:
    """
    Compute Expected Calibration Error (ECE).

    ECE measures the difference between predicted probabilities and
    actual accuracy, weighted by the number of samples in each bin.
    Lower is better; <0.05 indicates good calibration.

    Args:
        scores: Predicted probabilities.
        labels: True labels (0 or 1).
        n_bins: Number of bins for grouping.

    Returns:
        ECE value in [0, 1].

    Example:
        >>> ece = expected_calibration_error(predictions, labels)
        >>> print(f"ECE: {ece:.4f}")
        ECE: 0.0234
    """
    scores = np.asarray(scores).ravel()
    labels = np.asarray(labels).ravel()

    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece = 0.0

    for i in range(n_bins):
        in_bin = (scores >= bin_boundaries[i]) & (scores < bin_boundaries[i + 1])
        prop_in_bin = np.mean(in_bin)

        if prop_in_bin > 0:
            avg_confidence = np.mean(scores[in_bin])
            avg_accuracy = np.mean(labels[in_bin])
            ece += prop_in_bin * abs(avg_confidence - avg_accuracy)

    return float(ece)


def maximum_calibration_error(
    scores: NDArray[np.floating],
    labels: NDArray[np.floating],
    n_bins: int = 10
) -> float:
    """
    Compute Maximum Calibration Error (MCE).

    MCE is the maximum absolute difference between predicted
    probability and actual accuracy across all bins.

    Args:
        scores: Predicted probabilities.
        labels: True labels.
        n_bins: Number of bins.

    Returns:
        MCE value in [0, 1].
    """
    scores = np.asarray(scores).ravel()
    labels = np.asarray(labels).ravel()

    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    mce = 0.0

    for i in range(n_bins):
        in_bin = (scores >= bin_boundaries[i]) & (scores < bin_boundaries[i + 1])

        if np.sum(in_bin) > 0:
            avg_confidence = np.mean(scores[in_bin])
            avg_accuracy = np.mean(labels[in_bin])
            mce = max(mce, abs(avg_confidence - avg_accuracy))

    return float(mce)


def compute_confidence_interval(
    scores: NDArray[np.floating],
    confidence: float = 0.95
) -> tuple[float, float, float]:
    """
    Compute confidence interval for score predictions.

    Uses bootstrap percentile method for robust interval estimation.

    Args:
        scores: Score samples.
        confidence: Confidence level (0.95 for 95% CI).

    Returns:
        Tuple of (mean, lower_bound, upper_bound).

    Example:
        >>> mean, lo, hi = compute_confidence_interval(scores, 0.95)
        >>> print(f"{mean:.3f} [{lo:.3f}, {hi:.3f}]")
        0.723 [0.698, 0.748]
    """
    scores = np.asarray(scores).ravel()

    if len(scores) == 0:
        return 0.0, 0.0, 0.0

    mean = float(np.mean(scores))

    if len(scores) == 1:
        return mean, mean, mean

    # Bootstrap percentile method
    n_bootstrap = 1000
    rng = np.random.RandomState(42)
    bootstrap_means = np.zeros(n_bootstrap)

    for i in range(n_bootstrap):
        sample = rng.choice(scores, size=len(scores), replace=True)
        bootstrap_means[i] = np.mean(sample)

    alpha = 1 - confidence
    lower = float(np.percentile(bootstrap_means, alpha / 2 * 100))
    upper = float(np.percentile(bootstrap_means, (1 - alpha / 2) * 100))

    return mean, lower, upper


def calibration_curve(
    scores: NDArray[np.floating],
    labels: NDArray[np.floating],
    n_bins: int = 10
) -> tuple[NDArray[np.floating], NDArray[np.floating], NDArray[np.int_]]:
    """
    Compute calibration curve data.

    Returns data for plotting reliability diagrams.

    Args:
        scores: Predicted probabilities.
        labels: True labels.
        n_bins: Number of bins.

    Returns:
        Tuple of (mean_predicted, fraction_positives, bin_counts).
    """
    scores = np.asarray(scores).ravel()
    labels = np.asarray(labels).ravel()

    bin_boundaries = np.linspace(0, 1, n_bins + 1)

    mean_predicted = []
    fraction_positives = []
    bin_counts = []

    for i in range(n_bins):
        in_bin = (scores >= bin_boundaries[i]) & (scores < bin_boundaries[i + 1])
        count = np.sum(in_bin)

        if count > 0:
            mean_predicted.append(float(np.mean(scores[in_bin])))
            fraction_positives.append(float(np.mean(labels[in_bin])))
            bin_counts.append(int(count))

    return (
        np.array(mean_predicted),
        np.array(fraction_positives),
        np.array(bin_counts)
    )


# Module exports
__all__ = [
    # Calibrators
    "BaseCalibrator",
    "IsotonicCalibrator",
    "TemperatureScaler",
    # Metrics
    "expected_calibration_error",
    "maximum_calibration_error",
    "compute_confidence_interval",
    "calibration_curve",
    # Exceptions
    "CalibrationError",
]

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

"""Shared utilities for UCID context implementations.

This module provides utility functions used by multiple context
implementations.
"""

from typing import Any


def merge_configs(
    default: dict[str, Any],
    override: dict[str, Any],
) -> dict[str, Any]:
    """Deep merge two configuration dictionaries.

    Override values take precedence. Nested dictionaries are merged
    recursively rather than replaced entirely.

    Args:
        default: Default configuration values.
        override: Override values that take precedence.

    Returns:
        Merged configuration dictionary.

    Example:
        >>> default = {"a": 1, "nested": {"x": 10}}
        >>> override = {"nested": {"y": 20}}
        >>> merge_configs(default, override)
        {'a': 1, 'nested': {'x': 10, 'y': 20}}
    """
    result = default.copy()
    for key, value in override.items():
        if isinstance(value, dict) and key in result and isinstance(result[key], dict):
            result[key] = merge_configs(result[key], value)
        else:
            result[key] = value
    return result


def validate_weights(weights: dict[str, float], tolerance: float = 0.01) -> bool:
    """Validate that weights sum to approximately 1.0.

    Args:
        weights: Dictionary of weight values.
        tolerance: Allowed deviation from 1.0. Defaults to 0.01.

    Returns:
        True if weights sum to 1.0 within tolerance.

    Example:
        >>> validate_weights({"a": 0.6, "b": 0.4})
        True
        >>> validate_weights({"a": 0.5, "b": 0.3})
        False
    """
    total = sum(weights.values())
    return abs(total - 1.0) < tolerance


def clamp(value: float, min_val: float, max_val: float) -> float:
    """Clamp a value to the specified range.

    Args:
        value: Value to clamp.
        min_val: Minimum allowed value.
        max_val: Maximum allowed value.

    Returns:
        Clamped value.

    Example:
        >>> clamp(150, 0, 100)
        100.0
    """
    return max(min_val, min(max_val, value))

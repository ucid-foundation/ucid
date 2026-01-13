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

"""Visualization utilities for UCID.

This module provides map and chart generation for UCID data.
"""

from typing import Any

from ucid.core.models import UCID


def create_map(
    ucids: list[UCID],
    center: tuple[float, float] | None = None,
    zoom: int = 12,
) -> Any:
    """Create an interactive map of UCIDs.

    Args:
        ucids: List of UCID objects to display.
        center: Optional map center as (lat, lon).
        zoom: Initial zoom level.

    Returns:
        Folium map object (if folium installed) or dict representation.
    """
    try:
        import folium  # type: ignore[import-untyped]

        if center is None and ucids:
            center = (ucids[0].lat, ucids[0].lon)
        elif center is None:
            center = (0.0, 0.0)

        m = folium.Map(location=center, zoom_start=zoom)

        for ucid in ucids:
            folium.CircleMarker(
                location=(ucid.lat, ucid.lon),
                radius=5,
                popup=str(ucid),
                color=_grade_to_color(ucid.grade),
                fill=True,
            ).add_to(m)

        return m

    except ImportError:
        return {
            "type": "map",
            "center": center,
            "zoom": zoom,
            "points": [(u.lat, u.lon, u.grade) for u in ucids],
        }


def _grade_to_color(grade: str) -> str:
    """Map grade to display color.

    Args:
        grade: Letter grade.

    Returns:
        Color string for visualization.
    """
    colors = {
        "A+": "#1a9850",
        "A": "#66bd63",
        "B": "#a6d96a",
        "C": "#fdae61",
        "D": "#f46d43",
        "F": "#d73027",
    }
    return colors.get(grade, "#999999")


def create_score_chart(
    scores: list[float],
    labels: list[str] | None = None,
) -> dict[str, Any]:
    """Create a chart of scores.

    Args:
        scores: List of scores to chart.
        labels: Optional labels for x-axis.

    Returns:
        Chart configuration dict.
    """
    if labels is None:
        labels = [str(i) for i in range(len(scores))]

    return {
        "type": "bar",
        "data": {
            "labels": labels,
            "datasets": [
                {
                    "label": "Score",
                    "data": scores,
                    "backgroundColor": "#1a9850",
                }
            ],
        },
        "options": {
            "scales": {
                "y": {"min": 0, "max": 100},
            },
        },
    }

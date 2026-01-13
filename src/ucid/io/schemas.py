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

"""GeoJSON schema definitions for UCID data export.

This module provides Pydantic models for GeoJSON output,
enabling type-safe serialization of spatial data.
"""

from typing import Any

from pydantic import BaseModel, Field


class GeoJSONGeometry(BaseModel):
    """GeoJSON geometry object.

    Attributes:
        type: Geometry type (Point, Polygon, etc.).
        coordinates: Coordinate array appropriate for the type.
    """

    type: str = Field(..., description="Geometry type")
    coordinates: list[float] | list[list[float]] | list[list[list[float]]] = Field(..., description="Coordinates")


class GeoJSONFeature(BaseModel):
    """GeoJSON Feature object.

    Represents a single geographic feature with geometry and properties.

    Attributes:
        type: Always "Feature".
        geometry: The geometry of the feature.
        properties: Arbitrary properties for the feature.

    Example:
        >>> feature = GeoJSONFeature(
        ...     geometry={"type": "Point", "coordinates": [28.979, 41.015]},
        ...     properties={"city": "IST", "score": 85.0},
        ... )
    """

    type: str = Field(default="Feature", description="GeoJSON type")
    geometry: dict[str, Any] = Field(..., description="Feature geometry")
    properties: dict[str, Any] = Field(default_factory=dict, description="Feature properties")


class GeoJSONFeatureCollection(BaseModel):
    """GeoJSON FeatureCollection object.

    A collection of GeoJSON features.

    Attributes:
        type: Always "FeatureCollection".
        features: List of Feature objects.

    Example:
        >>> collection = GeoJSONFeatureCollection(features=[feature1, feature2])
        >>> print(collection.model_dump_json())
    """

    type: str = Field(default="FeatureCollection", description="GeoJSON type")
    features: list[GeoJSONFeature] = Field(default_factory=list, description="List of features")

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

"""Integration tests for OSM Overpass API client.

These tests verify the OSM client functionality with real API calls.
Requires internet connection to run.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from ucid.data.osm_client import OSMClient, POI_CATEGORIES

if TYPE_CHECKING:
    pass


@pytest.fixture
def baku_coords() -> tuple[float, float]:
    """Baku city center coordinates."""
    return (40.4093, 49.8671)


@pytest.fixture
def istanbul_coords() -> tuple[float, float]:
    """Istanbul city center coordinates."""
    return (41.0082, 28.9784)


class TestOSMClient:
    """Integration tests for OSMClient."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_query_amenities_returns_pois(
        self, baku_coords: tuple[float, float]
    ) -> None:
        """Test that amenity query returns POI data."""
        lat, lon = baku_coords

        async with OSMClient(use_cache=True) as client:
            pois = await client.query_amenities(
                lat=lat,
                lon=lon,
                radius=500,
                categories=["grocery", "healthcare"],
            )

        assert isinstance(pois, list)
        # May be empty depending on area, but structure should be correct
        if pois:
            assert "lat" in pois[0]
            assert "lon" in pois[0]
            assert "type" in pois[0]

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_query_transit_stops(
        self, istanbul_coords: tuple[float, float]
    ) -> None:
        """Test transit stop query for Istanbul."""
        lat, lon = istanbul_coords

        async with OSMClient(use_cache=True) as client:
            stops = await client.query_transit_stops(
                lat=lat,
                lon=lon,
                radius=1000,
            )

        assert isinstance(stops, list)
        if stops:
            assert "lat" in stops[0]
            assert "lon" in stops[0]
            assert "type" in stops[0]

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_query_pedestrian_infrastructure(
        self, baku_coords: tuple[float, float]
    ) -> None:
        """Test pedestrian infrastructure query."""
        lat, lon = baku_coords

        async with OSMClient(use_cache=True) as client:
            infra = await client.query_pedestrian_infrastructure(
                lat=lat,
                lon=lon,
                radius=300,
            )

        assert isinstance(infra, dict)
        assert "total_elements" in infra
        assert "ways" in infra
        assert "nodes" in infra

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_caching_works(
        self, baku_coords: tuple[float, float]
    ) -> None:
        """Test that caching prevents duplicate API calls."""
        lat, lon = baku_coords

        async with OSMClient(use_cache=True) as client:
            # First call - will hit API
            pois1 = await client.query_amenities(lat, lon, 200, ["grocery"])

            # Second call - should use cache
            pois2 = await client.query_amenities(lat, lon, 200, ["grocery"])

        # Results should be identical
        assert len(pois1) == len(pois2)

    def test_poi_categories_defined(self) -> None:
        """Test that POI categories are properly defined."""
        expected_categories = [
            "grocery",
            "healthcare",
            "education",
            "recreation",
            "food",
            "transport",
            "finance",
            "childcare",
        ]

        for category in expected_categories:
            assert category in POI_CATEGORIES
            assert isinstance(POI_CATEGORIES[category], list)
            assert len(POI_CATEGORIES[category]) > 0


class TestContextIntegration:
    """Integration tests for context algorithms with real data."""

    @pytest.mark.integration
    def test_fifteen_minute_context_with_fallback(self) -> None:
        """Test 15MIN context with fallback mode."""
        from ucid.contexts.fifteen_minute import FifteenMinuteContext

        context = FifteenMinuteContext()
        result = context.compute(lat=40.4093, lon=49.8671, timestamp="2026W01T12")

        assert result.raw_score >= 0
        assert result.raw_score <= 100
        assert result.grade in ["A+", "A", "B", "C", "D", "F"]
        assert result.confidence > 0

    @pytest.mark.integration
    def test_transit_context_with_fallback(self) -> None:
        """Test TRANSIT context with fallback mode."""
        from ucid.contexts.transit import TransitContext

        context = TransitContext()
        result = context.compute(lat=41.0082, lon=28.9784, timestamp="2026W01T08")

        assert result.raw_score >= 0
        assert result.raw_score <= 100
        assert result.grade in ["A+", "A", "B", "C", "D", "F"]

    @pytest.mark.integration
    def test_walkability_context_with_fallback(self) -> None:
        """Test WALK context with fallback mode."""
        from ucid.contexts.walkability import WalkabilityContext

        context = WalkabilityContext()
        result = context.compute(lat=52.5200, lon=13.4050, timestamp="2026W01T10")

        assert result.raw_score >= 0
        assert result.raw_score <= 100
        assert result.grade in ["A+", "A", "B", "C", "D", "F"]

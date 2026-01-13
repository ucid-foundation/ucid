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

"""Comprehensive unit tests for IO module."""

import tempfile
from pathlib import Path

import geopandas as gpd
from shapely.geometry import Point

from ucid.io import export_geojson, export_geoparquet, read_geoparquet


class TestExportGeoParquet:
    """Tests for export_geoparquet function."""

    def test_export_geoparquet_basic(self) -> None:
        """Test basic GeoParquet export."""
        # Create test GeoDataFrame
        gdf = gpd.GeoDataFrame(
            {"ucid": ["test1", "test2"], "score": [0.8, 0.9]},
            geometry=[Point(0, 0), Point(1, 1)],
            crs="EPSG:4326",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.parquet"
            export_geoparquet(gdf, path)
            assert path.exists()

    def test_export_geoparquet_with_metadata(self) -> None:
        """Test GeoParquet export with metadata."""
        gdf = gpd.GeoDataFrame(
            {"ucid": ["test1"], "score": [0.8]},
            geometry=[Point(28.979, 41.015)],
            crs="EPSG:4326",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.parquet"
            export_geoparquet(gdf, path)
            assert path.exists()
            assert path.stat().st_size > 0


class TestReadGeoParquet:
    """Tests for read_geoparquet function."""

    def test_read_geoparquet_basic(self) -> None:
        """Test basic GeoParquet read."""
        gdf = gpd.GeoDataFrame(
            {"ucid": ["test1", "test2"], "score": [0.8, 0.9]},
            geometry=[Point(0, 0), Point(1, 1)],
            crs="EPSG:4326",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.parquet"
            export_geoparquet(gdf, path)
            result = read_geoparquet(path)
            assert isinstance(result, gpd.GeoDataFrame)
            assert len(result) == 2

    def test_read_geoparquet_preserves_data(self) -> None:
        """Test that read preserves data."""
        gdf = gpd.GeoDataFrame(
            {"ucid": ["A", "B", "C"], "score": [0.1, 0.5, 0.9]},
            geometry=[Point(0, 0), Point(1, 1), Point(2, 2)],
            crs="EPSG:4326",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.parquet"
            export_geoparquet(gdf, path)
            result = read_geoparquet(path)
            assert list(result["ucid"]) == ["A", "B", "C"]


class TestExportGeoJSON:
    """Tests for export_geojson function."""

    def test_export_geojson_basic(self) -> None:
        """Test basic GeoJSON export."""
        gdf = gpd.GeoDataFrame(
            {"ucid": ["test1", "test2"], "score": [0.8, 0.9]},
            geometry=[Point(0, 0), Point(1, 1)],
            crs="EPSG:4326",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.geojson"
            export_geojson(gdf, path)
            assert path.exists()

    def test_export_geojson_content(self) -> None:
        """Test GeoJSON content is valid."""
        gdf = gpd.GeoDataFrame(
            {"ucid": ["test1"], "score": [0.8]},
            geometry=[Point(28.979, 41.015)],
            crs="EPSG:4326",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.geojson"
            export_geojson(gdf, path)
            content = path.read_text()
            assert "Feature" in content
            assert "geometry" in content

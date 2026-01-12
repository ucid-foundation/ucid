"""Test data fixtures."""
import pytest
from pathlib import Path
from ucid.core.parser import create_ucid

@pytest.fixture
def sample_cities():
    return {
        "IST": {"lat": 41.0082, "lon": 28.9784},
        "NYC": {"lat": 40.7128, "lon": -74.0060},
        "LON": {"lat": 51.5074, "lon": -0.1278}
    }

@pytest.fixture
def sample_ucids(sample_cities):
    ucids = []
    for code, coords in sample_cities.items():
        u = create_ucid(
            city=code, 
            lat=coords["lat"], 
            lon=coords["lon"],
            timestamp="2026W01T12",
            context="TEST",
            grade="A"
        )
        ucids.append(str(u))
    return ucids

@pytest.fixture
def mock_gtfs_path(tmp_path):
    """Create a dummy GTFS zip for testing."""
    d = tmp_path / "gtfs"
    d.mkdir()
    (d / "agency.txt").write_text("agency_id,agency_name\n1,Demo Transit")
    (d / "stops.txt").write_text("stop_id,stop_name,stop_lat,stop_lon\n1,Stop A,40.0,20.0")
    
    zip_path = tmp_path / "test.zip"
    import shutil
    shutil.make_archive(str(zip_path.with_suffix('')), 'zip', d)
    return zip_path

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

"""Official Data Sources Registry for UCID.

This module provides a curated registry of verified external datasets
that can be used with UCID, including GTFS feeds, real-time data, and
benchmark datasets for testing.
"""

from dataclasses import dataclass


@dataclass
class DatasetSource:
    """Definition of a verified external dataset.

    Contains metadata about a data source including its location,
    format, licensing, and intended use (benchmark vs showcase).

    Attributes:
        key: Unique identifier for this dataset.
        name: Human-readable name.
        description: Brief description of the dataset.
        url: URL to download or access the data.
        format: Data format ('gtfs', 'gtfs-rt', 'geojson', 'csv').
        region: Geographic region covered.
        license: License under which data is provided.
        is_benchmark: True if suitable for performance benchmarking.
        is_showcase: True if suitable for demos and examples.

    Example:
        >>> source = get_source("hsl_gtfs")
        >>> print(source.url)
    """

    key: str
    name: str
    description: str
    url: str
    format: str
    region: str
    license: str
    is_benchmark: bool = False
    is_showcase: bool = False


# Official Registry of UCID-Validated Datasets
DATASETS: dict[str, DatasetSource] = {
    "hsl_gtfs": DatasetSource(
        key="hsl_gtfs",
        name="Helsinki Region Transport GTFS",
        description="Official schedule data for Helsinki region (HSL).",
        url="https://infopalvelut.storage.hsldev.com/gtfs/hsl.zip",
        format="gtfs",
        region="Helsinki, FI",
        license="CC BY 4.0",
        is_showcase=True,
    ),
    "hsl_rt_alerts": DatasetSource(
        key="hsl_rt_alerts",
        name="HSL Service Alerts",
        description="Realtime service alerts for Helsinki public transport.",
        url="https://realtime.hsl.fi/realtime/service-alerts/v2/hsl",
        format="gtfs-rt",
        region="Helsinki, FI",
        license="CC BY 4.0",
        is_showcase=True,
    ),
    "hsl_rt_trip": DatasetSource(
        key="hsl_rt_trip",
        name="HSL Trip Updates",
        description="Realtime trip updates for Helsinki public transport.",
        url="https://realtime.hsl.fi/realtime/trip-updates/v2/hsl",
        format="gtfs-rt",
        region="Helsinki, FI",
        license="CC BY 4.0",
        is_showcase=True,
    ),
    "hsl_rt_vehicle": DatasetSource(
        key="hsl_rt_vehicle",
        name="HSL Vehicle Positions",
        description="Realtime vehicle positions for Helsinki public transport.",
        url="https://realtime.hsl.fi/realtime/vehicle-positions/v2/hsl",
        format="gtfs-rt",
        region="Helsinki, FI",
        license="CC BY 4.0",
        is_showcase=True,
    ),
    "pdx_gtfs": DatasetSource(
        key="pdx_gtfs",
        name="TriMet GTFS",
        description="Clean, mid-sized feed for Portland, ideal for CI.",
        url="http://developer.trimet.org/schedule/gtfs.zip",
        format="gtfs",
        region="Portland, OR, US",
        license="Open Data",
        is_benchmark=False,
    ),
    "nyc_subway_gtfs": DatasetSource(
        key="nyc_subway_gtfs",
        name="MTA NYCT Subway GTFS",
        description="Large, complex subway feed for edge-case testing.",
        url="https://rrgtfsfeeds.s3.amazonaws.com/gtfs_subway.zip",
        format="gtfs",
        region="New York, NY, US",
        license="MTA Developer License",
        is_benchmark=True,
    ),
    "bos_gtfs": DatasetSource(
        key="bos_gtfs",
        name="MBTA GTFS",
        description="Boston reference feed, reliable CDN hosting.",
        url="https://cdn.mbta.com/MBTA_GTFS.zip",
        format="gtfs",
        region="Boston, MA, US",
        license="MassDOT Developer License",
        is_benchmark=True,
    ),
    "syd_gtfs": DatasetSource(
        key="syd_gtfs",
        name="Transport for NSW GTFS",
        description="Massive benchmark dataset for Sydney region.",
        url=(
            "https://opendata.transport.nsw.gov.au/data/dataset/"
            "d1f68d4f-b778-44df-9823-cf2fa922e47f/resource/"
            "67974f14-01bf-47b7-bfa5-c7f2f8a950ca/download/"
            "full_greater_sydney_gtfs_static_0.zip"
        ),
        format="gtfs",
        region="Sydney, AU",
        license="Creative Commons Attribution 4.0",
        is_benchmark=True,
    ),
    "ist_gtfs_manual": DatasetSource(
        key="ist_gtfs_manual",
        name="IETT GTFS Data",
        description="Istanbul public transport data (Manual Download Required).",
        url="https://data.ibb.gov.tr/dataset/iett-hat-durak-ve-sefer-verileri-gtfs",
        format="gtfs",
        region="Istanbul, TR",
        license="IBB Open Data",
        is_showcase=True,
    ),
}


def get_source(key: str) -> DatasetSource | None:
    """Get a dataset source by its key.

    Args:
        key: The unique identifier for the dataset.

    Returns:
        The DatasetSource if found, None otherwise.

    Example:
        >>> source = get_source("hsl_gtfs")
        >>> if source:
        ...     print(f"URL: {source.url}")
    """
    return DATASETS.get(key)


def list_sources(tag: str | None = None) -> list[DatasetSource]:
    """List available dataset sources.

    Args:
        tag: Optional filter. Use 'benchmark' for benchmark datasets
            or 'showcase' for demo-suitable datasets.

    Returns:
        List of DatasetSource objects matching the filter.

    Example:
        >>> benchmarks = list_sources(tag="benchmark")
        >>> for src in benchmarks:
        ...     print(src.name)
    """
    if tag == "benchmark":
        return [s for s in DATASETS.values() if s.is_benchmark]
    if tag == "showcase":
        return [s for s in DATASETS.values() if s.is_showcase]
    return list(DATASETS.values())

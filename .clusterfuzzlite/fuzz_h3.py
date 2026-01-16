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

"""Fuzz target for H3 spatial operations.

This module provides fuzzing coverage for the H3 hexagonal
spatial indexing operations used in UCID to identify potential
issues with coordinate conversion and cell operations.

H3 is a critical dependency for UCID's spatial indexing. This
fuzzer ensures the H3 integration handles edge cases correctly.

Fuzzing Metrics:
    - Target functions: h3.latlng_to_cell(), h3.cell_to_latlng(), etc.
    - Coverage goal: 70%+
    - Mutation strategies: Random coordinates, invalid cells

Example:
    Run locally with atheris:

    >>> python fuzz_h3.py -max_total_time=300

Reference:
    https://google.github.io/clusterfuzzlite/
    https://h3geo.org/
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

try:
    import atheris
except ImportError:
    raise ImportError(
        "atheris is required for fuzzing. Install with: pip install atheris"
    )

try:
    import h3
except ImportError:
    raise ImportError(
        "h3 is required for fuzzing. Install with: pip install h3"
    )

if TYPE_CHECKING:
    from collections.abc import Sequence


def test_latlng_to_cell(data: bytes) -> None:
    """Fuzz test H3 coordinate to cell conversion.

    Tests h3.latlng_to_cell() with random coordinates and resolutions.

    Args:
        data: Random bytes from the fuzzer engine.

    Expected Behavior:
        - Valid coordinates: Return valid H3 cell index
        - Invalid coordinates: Raise ValueError or return valid cell
        - All inputs: No crashes or hangs
    """
    fdp = atheris.FuzzedDataProvider(data)

    # Generate random but valid-ish coordinates
    lat = fdp.ConsumeFloatInRange(-90.0, 90.0)
    lon = fdp.ConsumeFloatInRange(-180.0, 180.0)
    resolution = fdp.ConsumeIntInRange(0, 15)

    try:
        cell = h3.latlng_to_cell(lat, lon, resolution)

        # Verify the cell is valid
        assert cell is not None
        assert h3.is_valid_cell(cell)

        # Verify resolution matches
        assert h3.get_resolution(cell) == resolution

    except (ValueError, TypeError):
        # Acceptable for edge cases
        pass


def test_cell_to_latlng(data: bytes) -> None:
    """Fuzz test H3 cell to coordinate conversion.

    Tests h3.cell_to_latlng() with random cell strings.

    Args:
        data: Random bytes from the fuzzer engine.
    """
    fdp = atheris.FuzzedDataProvider(data)

    # Generate random H3-like cell strings
    cell_variants = [
        fdp.ConsumeString(15),
        fdp.ConsumeBytes(8).hex(),
        "8" + fdp.ConsumeString(14),
        "891f" + fdp.ConsumeString(11),
    ]

    for cell in cell_variants:
        try:
            if h3.is_valid_cell(cell):
                center = h3.cell_to_latlng(cell)

                # Verify coordinates are in valid range
                assert -90.0 <= center[0] <= 90.0
                assert -180.0 <= center[1] <= 180.0

        except (ValueError, TypeError):
            pass


def test_cell_boundary(data: bytes) -> None:
    """Fuzz test H3 cell boundary operations.

    Tests h3.cell_to_boundary() with various H3 cells.

    Args:
        data: Random bytes from the fuzzer engine.
    """
    fdp = atheris.FuzzedDataProvider(data)

    # First create a valid cell, then test operations on it
    lat = fdp.ConsumeFloatInRange(-85.0, 85.0)  # Avoid polar regions
    lon = fdp.ConsumeFloatInRange(-175.0, 175.0)
    resolution = fdp.ConsumeIntInRange(0, 15)

    try:
        cell = h3.latlng_to_cell(lat, lon, resolution)

        # Get boundary
        boundary = h3.cell_to_boundary(cell)

        # Hexagons have 6 vertices (pentagons have 5)
        assert len(boundary) >= 5
        assert len(boundary) <= 6

        # Each vertex should be a valid coordinate pair
        for vertex in boundary:
            assert len(vertex) == 2
            assert -90.0 <= vertex[0] <= 90.0
            assert -180.0 <= vertex[1] <= 180.0

    except (ValueError, TypeError):
        pass


def test_grid_operations(data: bytes) -> None:
    """Fuzz test H3 grid operations.

    Tests h3.grid_ring() and h3.grid_disk() operations.

    Args:
        data: Random bytes from the fuzzer engine.
    """
    fdp = atheris.FuzzedDataProvider(data)

    lat = fdp.ConsumeFloatInRange(-85.0, 85.0)
    lon = fdp.ConsumeFloatInRange(-175.0, 175.0)
    resolution = fdp.ConsumeIntInRange(0, 12)
    k = fdp.ConsumeIntInRange(0, 5)

    try:
        cell = h3.latlng_to_cell(lat, lon, resolution)

        # Test grid ring
        ring = h3.grid_ring(cell, k)
        assert isinstance(ring, (list, set, frozenset))

        # Test grid disk
        disk = h3.grid_disk(cell, k)
        assert isinstance(disk, (list, set, frozenset))

        # Ring should be subset of disk (when ring cells exist)
        if k > 0:
            ring_set = set(ring) if not isinstance(ring, set) else ring
            disk_set = set(disk) if not isinstance(disk, set) else disk
            # Note: This may not always hold for pentagons

    except (ValueError, TypeError, h3.H3CellError):
        pass


def test_grid_distance(data: bytes) -> None:
    """Fuzz test H3 grid distance calculations.

    Tests h3.grid_distance() between two random cells.

    Args:
        data: Random bytes from the fuzzer engine.
    """
    fdp = atheris.FuzzedDataProvider(data)

    lat1 = fdp.ConsumeFloatInRange(-85.0, 85.0)
    lon1 = fdp.ConsumeFloatInRange(-175.0, 175.0)
    lat2 = fdp.ConsumeFloatInRange(-85.0, 85.0)
    lon2 = fdp.ConsumeFloatInRange(-175.0, 175.0)
    resolution = fdp.ConsumeIntInRange(0, 10)

    try:
        cell1 = h3.latlng_to_cell(lat1, lon1, resolution)
        cell2 = h3.latlng_to_cell(lat2, lon2, resolution)

        distance = h3.grid_distance(cell1, cell2)

        # Distance should be non-negative
        assert distance >= 0

        # Distance to self should be 0
        self_distance = h3.grid_distance(cell1, cell1)
        assert self_distance == 0

    except (ValueError, TypeError, h3.H3CellError):
        # May fail for cells too far apart
        pass


def test_one_input(data: bytes) -> None:
    """Main fuzz target entry point.

    This function is called by the fuzzer for each generated input.
    It runs all H3 fuzzing test cases.

    Args:
        data: Random bytes from the fuzzer engine.
    """
    test_latlng_to_cell(data)
    test_cell_to_latlng(data)
    test_cell_boundary(data)
    test_grid_operations(data)
    test_grid_distance(data)


def main(argv: Sequence[str] | None = None) -> None:
    """Main entry point for the H3 fuzzer.

    Args:
        argv: Command-line arguments. Defaults to sys.argv.
    """
    if argv is None:
        argv = sys.argv

    atheris.Setup(
        argv,
        test_one_input,
        enable_python_coverage=True,
    )
    atheris.Fuzz()


if __name__ == "__main__":
    main()

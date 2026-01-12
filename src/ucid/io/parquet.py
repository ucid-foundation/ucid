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

"""Parquet file operations for UCID data.

This module provides functions for reading and writing UCID data
in Apache Parquet format for efficient storage and processing.
"""

from pathlib import Path
from typing import Any

import pandas as pd


def write_parquet(
    data: list[dict[str, Any]],
    path: str | Path,
    compression: str = "snappy",
) -> None:
    """Write a list of dictionaries to a Parquet file.

    Args:
        data: List of dictionaries to write.
        path: Path to the output Parquet file.
        compression: Compression algorithm. Defaults to "snappy".
            Options: snappy, gzip, brotli, zstd, None.

    Example:
        >>> data = [{"city": "IST", "score": 85.0}]
        >>> write_parquet(data, "output.parquet")
    """
    df = pd.DataFrame(data)
    df.to_parquet(path, compression=compression, index=False)


def read_parquet(path: str | Path) -> list[dict[str, Any]]:
    """Read a Parquet file into a list of dictionaries.

    Args:
        path: Path to the Parquet file.

    Returns:
        List of dictionaries, one per row.

    Example:
        >>> data = read_parquet("input.parquet")
        >>> print(data[0]["city"])
    """
    df = pd.read_parquet(path)
    return df.to_dict("records")


def read_parquet_df(path: str | Path) -> pd.DataFrame:
    """Read a Parquet file into a pandas DataFrame.

    Args:
        path: Path to the Parquet file.

    Returns:
        DataFrame containing the data.
    """
    return pd.read_parquet(path)

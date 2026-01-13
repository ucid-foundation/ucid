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

"""UCID Sample Data Downloader.

This module provides utilities for downloading official UCID datasets from
verified sources. It supports GTFS feeds, OSM extracts, and other urban
data sources required for UCID analysis.

Example:
    >>> from scripts.download_sample_data import download_file
    >>> result = download_file("https://example.com/data.zip", Path("data.zip"))
    >>> print(result.success)
    True
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError

from ucid.data.sources import get_source, list_sources

# Configuration
DEFAULT_OUTPUT_DIR = "data/external"
CHUNK_SIZE = 8192
USER_AGENT = "UCID-Downloader/1.0"


@dataclass
class DownloadResult:
    """Result of a download operation.

    Attributes:
        source_key: Key identifier for the source.
        success: Whether the download succeeded.
        path: Path to downloaded file, if successful.
        message: Status message.
        bytes_downloaded: Number of bytes downloaded.
    """

    source_key: str
    success: bool
    path: Path | None
    message: str
    bytes_downloaded: int = 0


def calculate_sha256(filepath: Path) -> str:
    """Calculate SHA256 checksum of a file.

    Args:
        filepath: Path to file.

    Returns:
        Hexadecimal SHA256 digest.
    """
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def download_file(
    url: str,
    dest: Path,
    expected_checksum: str | None = None,
    show_progress: bool = True,
) -> DownloadResult:
    """Download a file with progress indication.

    Args:
        url: URL to download from.
        dest: Destination path.
        expected_checksum: Optional SHA256 checksum for verification.
        show_progress: Whether to show progress indicator.

    Returns:
        DownloadResult with download status.
    """
    print(f"  Downloading: {url}")
    print(f"  Destination: {dest}")

    try:
        request = urllib.request.Request(url)
        request.add_header("User-Agent", USER_AGENT)

        with urllib.request.urlopen(request, timeout=60) as response:
            total_size = int(response.info().get("Content-Length", 0))
            downloaded = 0

            dest.parent.mkdir(parents=True, exist_ok=True)

            with open(dest, "wb") as f:
                while True:
                    chunk = response.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)

                    if show_progress and total_size > 0:
                        percent = (downloaded / total_size) * 100
                        bar_length = 40
                        filled = int(bar_length * downloaded / total_size)
                        bar = "=" * filled + "-" * (bar_length - filled)
                        size_mb = downloaded / (1024 * 1024)
                        sys.stdout.write(f"\r  Progress: [{bar}] {percent:5.1f}% ({size_mb:.1f} MB)")
                        sys.stdout.flush()

            if show_progress:
                print()

        if expected_checksum:
            actual_checksum = calculate_sha256(dest)
            if actual_checksum != expected_checksum:
                dest.unlink()
                return DownloadResult(
                    source_key=dest.stem,
                    success=False,
                    path=None,
                    message="Checksum mismatch",
                    bytes_downloaded=downloaded,
                )

        return DownloadResult(
            source_key=dest.stem,
            success=True,
            path=dest,
            message="Downloaded successfully",
            bytes_downloaded=downloaded,
        )

    except HTTPError as e:
        return DownloadResult(
            source_key=dest.stem,
            success=False,
            path=None,
            message=f"HTTP Error {e.code}: {e.reason}",
        )
    except URLError as e:
        return DownloadResult(
            source_key=dest.stem,
            success=False,
            path=None,
            message=f"URL Error: {e.reason}",
        )
    except Exception as e:
        return DownloadResult(
            source_key=dest.stem,
            success=False,
            path=None,
            message=f"Error: {e}",
        )


def list_available_sources() -> None:
    """Print list of available data sources."""
    print()
    print("=" * 70)
    print("Available Data Sources")
    print("=" * 70)
    print()
    print(f"{'Key':<15} {'Name':<25} {'Region':<15} {'Type':<15}")
    print("-" * 70)

    for source in list_sources():
        source_type = "Benchmark" if source.is_benchmark else "Standard"
        print(f"{source.key:<15} {source.name:<25} {source.region:<15} {source_type:<15}")

    print("-" * 70)
    print()
    print("Usage:")
    print("  --all         Download all automated datasets")
    print("  --ci          Download CI/Test datasets only")
    print("  --source KEY  Download specific source")
    print()


def download_sources(sources: list, output_dir: Path) -> list[DownloadResult]:
    """Download multiple data sources.

    Args:
        sources: List of source objects.
        output_dir: Output directory path.

    Returns:
        List of download results.
    """
    results: list[DownloadResult] = []

    print()
    print(f"Downloading {len(sources)} dataset(s) to '{output_dir}'")
    print()

    for i, source in enumerate(sources, 1):
        print(f"[{i}/{len(sources)}] {source.name}")

        if "manual" in source.key:
            print(f"  SKIP: Requires manual download from {source.url}")
            results.append(
                DownloadResult(
                    source_key=source.key,
                    success=True,
                    path=None,
                    message="Manual download required",
                )
            )
            continue

        extension = ".zip" if source.url.endswith(".zip") else ".dat"
        filename = f"{source.key}{extension}"
        dest = output_dir / filename

        if dest.exists():
            print("  SKIP: File already exists")
            results.append(
                DownloadResult(
                    source_key=source.key,
                    success=True,
                    path=dest,
                    message="Already downloaded",
                )
            )
            continue

        result = download_file(source.url, dest)
        results.append(result)

        status = "SUCCESS" if result.success else "FAILED"
        print(f"  {status}: {result.message}")
        print()

    return results


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Download verified UCID datasets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Download all automated datasets",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="Download CI/Test datasets only",
    )
    parser.add_argument(
        "--source",
        type=str,
        metavar="KEY",
        help="Download specific source by key",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=DEFAULT_OUTPUT_DIR,
        metavar="DIR",
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    return parser.parse_args()


def main() -> int:
    """Main entry point for the download script.

    Returns:
        0 on success, 1 on failure.
    """
    args = parse_args()
    output_dir = Path(args.output)

    sources_to_download = []

    if args.source:
        source = get_source(args.source)
        if source:
            sources_to_download.append(source)
        else:
            print(f"Error: Source '{args.source}' not found.")
            return 1
    elif args.ci:
        pdx = get_source("pdx_gtfs")
        if pdx:
            sources_to_download.append(pdx)
    elif args.all:
        sources_to_download = [s for s in list_sources() if "manual" not in s.key]
    else:
        list_available_sources()
        return 0

    output_dir.mkdir(parents=True, exist_ok=True)
    results = download_sources(sources_to_download, output_dir)

    return 0 if all(r.success for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())

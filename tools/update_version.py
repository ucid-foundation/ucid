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

"""Version management tool for UCID repository.

This tool updates version numbers across all project files to ensure
consistency. It supports semantic versioning and can automatically
bump versions.

Usage:
    python tools/update_version.py [VERSION] [options]

Examples:
    # Set specific version
    python tools/update_version.py 1.0.6

    # Bump patch version (1.0.5 -> 1.0.6)
    python tools/update_version.py --bump patch

    # Bump minor version (1.0.5 -> 1.1.0)
    python tools/update_version.py --bump minor

    # Bump major version (1.0.5 -> 2.0.0)
    python tools/update_version.py --bump major

    # Dry run (show changes without applying)
    python tools/update_version.py 1.0.6 --dry-run

Files Updated:
    - pyproject.toml
    - src/ucid/__init__.py
    - VERSION
    - CITATION.cff

Semantic Versioning:
    MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]

    - MAJOR: Incompatible API changes
    - MINOR: Backwards-compatible functionality
    - PATCH: Backwards-compatible bug fixes
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

# Version pattern (semantic versioning)
VERSION_PATTERN = re.compile(
    r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"(?:-(?P<prerelease>[a-zA-Z0-9.]+))?"
    r"(?:\+(?P<build>[a-zA-Z0-9.]+))?$"
)


@dataclass
class Version:
    """Semantic version representation."""

    major: int
    minor: int
    patch: int
    prerelease: str | None = None
    build: str | None = None

    @classmethod
    def parse(cls, version_string: str) -> "Version":
        """Parse version string.

        Args:
            version_string: Version string to parse.

        Returns:
            Version object.

        Raises:
            ValueError: If version string is invalid.
        """
        match = VERSION_PATTERN.match(version_string.strip())
        if not match:
            raise ValueError(f"Invalid version format: {version_string}")

        return cls(
            major=int(match.group("major")),
            minor=int(match.group("minor")),
            patch=int(match.group("patch")),
            prerelease=match.group("prerelease"),
            build=match.group("build"),
        )

    def __str__(self) -> str:
        """Convert to string."""
        version = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            version += f"-{self.prerelease}"
        if self.build:
            version += f"+{self.build}"
        return version

    def bump_major(self) -> "Version":
        """Bump major version."""
        return Version(self.major + 1, 0, 0)

    def bump_minor(self) -> "Version":
        """Bump minor version."""
        return Version(self.major, self.minor + 1, 0)

    def bump_patch(self) -> "Version":
        """Bump patch version."""
        return Version(self.major, self.minor, self.patch + 1)


def get_current_version(root_path: Path) -> Version:
    """Get current version from VERSION file.

    Args:
        root_path: Repository root path.

    Returns:
        Current version.
    """
    version_file = root_path / "VERSION"
    if version_file.exists():
        content = version_file.read_text(encoding="utf-8").strip()
        return Version.parse(content)

    # Fallback to pyproject.toml
    pyproject = root_path / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text(encoding="utf-8")
        match = re.search(r'version\s*=\s*"([^"]+)"', content)
        if match:
            return Version.parse(match.group(1))

    raise ValueError("Could not determine current version")


def update_file(
    file_path: Path,
    old_version: str,
    new_version: str,
    patterns: list[tuple[str, str]],
    dry_run: bool = False,
) -> bool:
    """Update version in a file.

    Args:
        file_path: Path to file.
        old_version: Old version string.
        new_version: New version string.
        patterns: List of (pattern, replacement) tuples.
        dry_run: If True, don't write changes.

    Returns:
        True if file was modified.
    """
    if not file_path.exists():
        return False

    content = file_path.read_text(encoding="utf-8")
    original = content

    for pattern, replacement in patterns:
        content = re.sub(pattern, replacement, content)

    if content != original:
        if not dry_run:
            file_path.write_text(content, encoding="utf-8")
        return True

    return False


def update_version(
    root_path: Path,
    new_version: Version,
    dry_run: bool = False,
) -> dict[str, bool]:
    """Update version across all project files.

    Args:
        root_path: Repository root path.
        new_version: New version to set.
        dry_run: If True, don't write changes.

    Returns:
        Dictionary of file paths and whether they were modified.
    """
    new_ver_str = str(new_version)
    results = {}

    # VERSION file
    version_file = root_path / "VERSION"
    if not dry_run:
        version_file.write_text(new_ver_str + "\n", encoding="utf-8")
    results["VERSION"] = True

    # pyproject.toml
    results["pyproject.toml"] = update_file(
        root_path / "pyproject.toml",
        "",
        new_ver_str,
        [(r'version\s*=\s*"[^"]+"', f'version = "{new_ver_str}"')],
        dry_run,
    )

    # src/ucid/__init__.py
    results["src/ucid/__init__.py"] = update_file(
        root_path / "src" / "ucid" / "__init__.py",
        "",
        new_ver_str,
        [(r'__version__\s*=\s*"[^"]+"', f'__version__ = "{new_ver_str}"')],
        dry_run,
    )

    # CITATION.cff
    results["CITATION.cff"] = update_file(
        root_path / "CITATION.cff",
        "",
        new_ver_str,
        [(r"version:\s*[^\n]+", f"version: {new_ver_str}")],
        dry_run,
    )

    return results


def main(argv: Sequence[str] | None = None) -> int:
    """Main entry point for version updater.

    Args:
        argv: Command-line arguments.

    Returns:
        Exit code.
    """
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "version",
        nargs="?",
        help="New version (e.g., 1.0.6)",
    )
    parser.add_argument(
        "--bump",
        choices=["major", "minor", "patch"],
        help="Bump version (major, minor, or patch)",
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path.cwd(),
        help="Repository root path",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show changes without applying",
    )

    args = parser.parse_args(argv)

    # Get current version
    try:
        current = get_current_version(args.path)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"Current version: {current}")

    # Determine new version
    if args.version:
        try:
            new_version = Version.parse(args.version)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
    elif args.bump:
        if args.bump == "major":
            new_version = current.bump_major()
        elif args.bump == "minor":
            new_version = current.bump_minor()
        else:
            new_version = current.bump_patch()
    else:
        parser.error("Either VERSION or --bump is required")
        return 1

    print(f"New version: {new_version}")

    if args.dry_run:
        print("\n[DRY RUN] The following files would be updated:")
    else:
        print("\nUpdating files...")

    # Update version
    results = update_version(args.path, new_version, args.dry_run)

    for file_path, modified in results.items():
        status = "updated" if modified else "skipped"
        print(f"  {file_path}: {status}")

    if args.dry_run:
        print("\n[DRY RUN] No files were modified")
    else:
        print("\nVersion update complete!")

    return 0


if __name__ == "__main__":
    sys.exit(main())

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

"""License compliance checker for UCID repository.

This tool scans the repository for license compliance issues, verifying
that all source files have proper license headers and that third-party
dependencies have compatible licenses.

Usage:
    python tools/check_licenses.py [options]

Examples:
    # Check all files
    python tools/check_licenses.py

    # Generate JSON report
    python tools/check_licenses.py --report compliance.json

    # Check specific directory
    python tools/check_licenses.py --path src/ucid

Supported License:
    EUPL-1.2 (European Union Public License 1.2)

Compatible Licenses:
    - MIT
    - Apache-2.0
    - BSD-2-Clause
    - BSD-3-Clause
    - ISC
    - LGPL-2.1
    - LGPL-3.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

# License header pattern
LICENSE_HEADER_PATTERN = re.compile(
    r"Copyright\s+\d{4}\s+UCID\s+Foundation.*EUPL",
    re.IGNORECASE | re.DOTALL,
)

# Compatible licenses for dependencies
COMPATIBLE_LICENSES = frozenset({
    "MIT",
    "Apache-2.0",
    "Apache Software License",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSD License",
    "ISC",
    "LGPL-2.1",
    "LGPL-3.0",
    "PSF-2.0",
    "Python Software Foundation License",
    "EUPL-1.2",
})

# File extensions to check
SOURCE_EXTENSIONS = frozenset({".py", ".sh"})

# Directories to skip
SKIP_DIRECTORIES = frozenset({
    ".git",
    ".mypy_cache",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    ".venv",
    "venv",
    ".tox",
})


@dataclass
class ComplianceReport:
    """License compliance report."""

    total_files: int = 0
    compliant_files: int = 0
    non_compliant_files: list[str] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)
    dependency_issues: list[dict] = field(default_factory=list)

    @property
    def compliance_rate(self) -> float:
        """Calculate compliance rate as percentage."""
        if self.total_files == 0:
            return 100.0
        return (self.compliant_files / self.total_files) * 100

    def to_dict(self) -> dict:
        """Convert report to dictionary."""
        return {
            "total_files": self.total_files,
            "compliant_files": self.compliant_files,
            "non_compliant_files": self.non_compliant_files,
            "skipped_files": self.skipped_files,
            "dependency_issues": self.dependency_issues,
            "compliance_rate": f"{self.compliance_rate:.2f}%",
        }


def check_file_license(file_path: Path) -> bool:
    """Check if a file has a proper license header.

    Args:
        file_path: Path to the file to check.

    Returns:
        True if the file has a proper license header.
    """
    try:
        content = file_path.read_text(encoding="utf-8")
        # Check first 50 lines for license header
        header = "\n".join(content.split("\n")[:50])
        return bool(LICENSE_HEADER_PATTERN.search(header))
    except (OSError, UnicodeDecodeError):
        return False


def find_source_files(root_path: Path) -> list[Path]:
    """Find all source files in the repository.

    Args:
        root_path: Root directory to search.

    Returns:
        List of source file paths.
    """
    files = []

    for path in root_path.rglob("*"):
        # Skip directories in exclusion list
        if any(skip in path.parts for skip in SKIP_DIRECTORIES):
            continue

        # Check if it's a source file
        if path.is_file() and path.suffix in SOURCE_EXTENSIONS:
            files.append(path)

    return files


def check_dependencies() -> list[dict]:
    """Check third-party dependency licenses.

    Returns:
        List of dependency issues.
    """
    issues = []

    try:
        import importlib.metadata as metadata

        # Get installed packages
        for dist in metadata.distributions():
            license_info = dist.metadata.get("License", "Unknown")
            classifiers = dist.metadata.get_all("Classifier") or []

            # Extract license from classifiers
            license_classifiers = [
                c.split(" :: ")[-1]
                for c in classifiers
                if c.startswith("License")
            ]

            # Check if license is compatible
            all_licenses = {license_info} | set(license_classifiers)
            is_compatible = any(
                lic in COMPATIBLE_LICENSES or "OSI Approved" in lic
                for lic in all_licenses
            )

            if not is_compatible and license_info != "Unknown":
                issues.append({
                    "package": dist.metadata["Name"],
                    "version": dist.metadata["Version"],
                    "license": license_info,
                    "compatible": False,
                })
    except ImportError:
        pass

    return issues


def generate_report(
    root_path: Path,
    check_deps: bool = True,
) -> ComplianceReport:
    """Generate license compliance report.

    Args:
        root_path: Root directory to check.
        check_deps: Whether to check dependencies.

    Returns:
        Compliance report.
    """
    report = ComplianceReport()

    # Find and check source files
    source_files = find_source_files(root_path)

    for file_path in source_files:
        report.total_files += 1

        if check_file_license(file_path):
            report.compliant_files += 1
        else:
            report.non_compliant_files.append(str(file_path))

    # Check dependencies
    if check_deps:
        report.dependency_issues = check_dependencies()

    return report


def print_report(report: ComplianceReport) -> None:
    """Print compliance report to console.

    Args:
        report: Compliance report to print.
    """
    print("\n" + "=" * 60)
    print("UCID License Compliance Report")
    print("=" * 60)

    print(f"\nFiles Checked: {report.total_files}")
    print(f"Compliant: {report.compliant_files}")
    print(f"Non-Compliant: {len(report.non_compliant_files)}")
    print(f"Compliance Rate: {report.compliance_rate:.2f}%")

    if report.non_compliant_files:
        print("\nNon-Compliant Files:")
        for file_path in report.non_compliant_files[:10]:
            print(f"  - {file_path}")
        if len(report.non_compliant_files) > 10:
            print(f"  ... and {len(report.non_compliant_files) - 10} more")

    if report.dependency_issues:
        print("\nDependency License Issues:")
        for issue in report.dependency_issues:
            print(f"  - {issue['package']} ({issue['license']})")

    print("\n" + "=" * 60)


def main(argv: Sequence[str] | None = None) -> int:
    """Main entry point for license checker.

    Args:
        argv: Command-line arguments.

    Returns:
        Exit code (0 for success, 1 for issues found).
    """
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path.cwd(),
        help="Root path to check (default: current directory)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="Output JSON report to file",
    )
    parser.add_argument(
        "--no-deps",
        action="store_true",
        help="Skip dependency license check",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with error if any issues found",
    )

    args = parser.parse_args(argv)

    # Generate report
    report = generate_report(args.path, check_deps=not args.no_deps)

    # Print report
    print_report(report)

    # Save JSON report if requested
    if args.report:
        args.report.write_text(
            json.dumps(report.to_dict(), indent=2),
            encoding="utf-8",
        )
        print(f"Report saved to: {args.report}")

    # Determine exit code
    if args.strict and (report.non_compliant_files or report.dependency_issues):
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

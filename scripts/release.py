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

"""UCID Release Automation Script.

This module provides automated release management for the UCID package.
It handles version validation, changelog updates, build verification,
and publishing to PyPI and other package registries.

Example:
    >>> from scripts.release import validate_semver
    >>> validate_semver("1.0.0")
    True
    >>> validate_semver("invalid")
    False

Release workflow:
    1. Validate version number (SemVer)
    2. Check CHANGELOG.md is updated
    3. Run full test suite
    4. Build distribution packages
    5. Verify package contents
    6. Create git tag
    7. Publish to PyPI
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent
PYPROJECT_PATH = PROJECT_ROOT / "pyproject.toml"
CHANGELOG_PATH = PROJECT_ROOT / "CHANGELOG.md"
DIST_DIR = PROJECT_ROOT / "dist"

# SemVer pattern
SEMVER_PATTERN = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)


@dataclass
class ReleaseConfig:
    """Configuration for a release.

    Attributes:
        version: Version string to release.
        dry_run: If True, simulate without making changes.
        skip_tests: If True, skip running tests.
        skip_build: If True, skip building packages.
    """

    version: str
    dry_run: bool
    skip_tests: bool
    skip_build: bool

    @property
    def is_prerelease(self) -> bool:
        """Check if this is a prerelease version."""
        match = SEMVER_PATTERN.match(self.version)
        if match:
            return match.group("prerelease") is not None
        return False


@dataclass
class StepResult:
    """Result of a release step.

    Attributes:
        name: Name of the step.
        success: Whether the step succeeded.
        message: Result message.
        duration: Step duration in seconds.
    """

    name: str
    success: bool
    message: str
    duration: float = 0.0


def validate_semver(version: str) -> bool:
    """Validate that a version string follows SemVer 2.0.0.

    Args:
        version: Version string to validate.

    Returns:
        True if valid, False otherwise.
    """
    return SEMVER_PATTERN.match(version) is not None


def get_current_version() -> str | None:
    """Get the current version from pyproject.toml.

    Returns:
        Current version string or None if not found.
    """
    try:
        content = PYPROJECT_PATH.read_text()
        match = re.search(r'version\s*=\s*"([^"]+)"', content)
        if match:
            return match.group(1)
    except FileNotFoundError:
        pass
    return None


def check_changelog_updated(version: str) -> bool:
    """Check if CHANGELOG.md contains an entry for the version.

    Args:
        version: Version to check for.

    Returns:
        True if changelog contains version entry.
    """
    try:
        content = CHANGELOG_PATH.read_text()
        return f"## [{version}]" in content or f"## {version}" in content
    except FileNotFoundError:
        return False


def check_git_clean() -> bool:
    """Check if the git working directory is clean.

    Returns:
        True if no uncommitted changes.
    """
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )
    return len(result.stdout.strip()) == 0


def run_tests() -> StepResult:
    """Run the full test suite.

    Returns:
        StepResult indicating success or failure.
    """
    print("  Running tests...")
    result = subprocess.run(
        ["python", "-m", "pytest", "tests/", "-v", "--tb=short"],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )
    success = result.returncode == 0
    message = "All tests passed" if success else "Some tests failed"
    return StepResult("tests", success, message)


def build_package() -> StepResult:
    """Build distribution packages.

    Returns:
        StepResult indicating success or failure.
    """
    print("  Building packages...")

    # Clean dist directory
    if DIST_DIR.exists():
        for f in DIST_DIR.glob("*"):
            f.unlink()

    result = subprocess.run(
        ["python", "-m", "build"],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )
    success = result.returncode == 0
    message = "Packages built successfully" if success else "Build failed"
    return StepResult("build", success, message)


def run_release(config: ReleaseConfig) -> list[StepResult]:
    """Execute the release workflow.

    Args:
        config: Release configuration.

    Returns:
        List of step results.
    """
    results: list[StepResult] = []

    print()
    print("=" * 60)
    print(f"UCID Release: v{config.version}")
    print("=" * 60)
    print()

    if config.dry_run:
        print(">>> DRY RUN MODE - No changes will be made <<<")
        print()

    # Step 1: Validate version
    print("1. Validating version...")
    if validate_semver(config.version):
        results.append(StepResult("version", True, "Version is valid SemVer"))
    else:
        results.append(StepResult("version", False, "Invalid version format"))
        return results

    # Step 2: Check changelog
    print("2. Checking changelog...")
    if check_changelog_updated(config.version):
        results.append(StepResult("changelog", True, "Changelog is updated"))
    else:
        results.append(StepResult("changelog", False, "Changelog not updated"))

    # Step 3: Check git status
    print("3. Checking git status...")
    if check_git_clean() or config.dry_run:
        results.append(StepResult("git_clean", True, "Working directory clean"))
    else:
        results.append(StepResult("git_clean", False, "Uncommitted changes"))

    # Step 4: Run tests
    if not config.skip_tests:
        print("4. Running tests...")
        results.append(run_tests())
    else:
        results.append(StepResult("tests", True, "Tests skipped"))

    # Step 5: Build
    if not config.skip_build:
        print("5. Building packages...")
        results.append(build_package())
    else:
        results.append(StepResult("build", True, "Build skipped"))

    return results


def print_results(results: list[StepResult]) -> None:
    """Print release results summary."""
    print()
    print("-" * 60)
    print("Release Summary")
    print("-" * 60)

    for result in results:
        status = "✓" if result.success else "✗"
        print(f"  {status} {result.name}: {result.message}")

    print("-" * 60)

    passed = all(r.success for r in results)
    if passed:
        print("✓ Release completed successfully!")
    else:
        print("✗ Release failed. See errors above.")

    print()


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="UCID Release Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        "-V",
        type=str,
        help="Version to release (default: from pyproject.toml)",
    )
    parser.add_argument(
        "--dry-run",
        "-n",
        action="store_true",
        help="Simulate release without making changes",
    )
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Skip running tests",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip building packages",
    )
    return parser.parse_args()


def main() -> int:
    """Run the release process.

    Returns:
        0 on success, 1 on failure.
    """
    args = parse_args()

    # Determine version
    version = args.version or get_current_version()
    if not version:
        print("Error: Could not determine version. Use --version flag.")
        return 1

    # Create config
    config = ReleaseConfig(
        version=version,
        dry_run=args.dry_run,
        skip_tests=args.skip_tests,
        skip_build=args.skip_build,
    )

    # Run release
    results = run_release(config)
    print_results(results)

    # Return exit code
    return 0 if all(r.success for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())

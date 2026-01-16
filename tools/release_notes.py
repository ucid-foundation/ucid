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

"""Release notes generator for UCID repository.

This tool generates release notes from git history using conventional
commit format. It groups changes by type and formats them for release.

Usage:
    python tools/release_notes.py [options]

Examples:
    # Generate notes for specific version
    python tools/release_notes.py --version 1.0.6

    # Generate notes between tags
    python tools/release_notes.py --from v1.0.5 --to v1.0.6

    # Output to file
    python tools/release_notes.py --version 1.0.6 --output RELEASE_NOTES.md

Conventional Commit Types:
    feat:     New features
    fix:      Bug fixes
    docs:     Documentation changes
    style:    Code style changes
    refactor: Code refactoring
    perf:     Performance improvements
    test:     Test updates
    chore:    Maintenance tasks
    ci:       CI/CD changes
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


# Conventional commit pattern
COMMIT_PATTERN = re.compile(
    r"^(?P<type>feat|fix|docs|style|refactor|perf|test|chore|ci|build)"
    r"(?:\((?P<scope>[^)]+)\))?"
    r"(?P<breaking>!)?"
    r":\s*(?P<message>.+)$",
    re.IGNORECASE,
)

# Commit type labels
TYPE_LABELS = {
    "feat": "Features",
    "fix": "Bug Fixes",
    "docs": "Documentation",
    "style": "Code Style",
    "refactor": "Refactoring",
    "perf": "Performance",
    "test": "Tests",
    "chore": "Maintenance",
    "ci": "CI/CD",
    "build": "Build",
}


@dataclass
class Commit:
    """Parsed commit information."""

    hash: str
    type: str
    scope: str | None
    message: str
    breaking: bool
    author: str
    date: str


@dataclass
class ReleaseNotes:
    """Release notes structure."""

    version: str
    date: str
    breaking_changes: list[Commit] = field(default_factory=list)
    commits_by_type: dict[str, list[Commit]] = field(default_factory=dict)

    def to_markdown(self) -> str:
        """Generate Markdown release notes."""
        lines = [
            f"# Release {self.version}",
            "",
            f"**Release Date:** {self.date}",
            "",
        ]

        # Breaking changes
        if self.breaking_changes:
            lines.extend([
                "## Breaking Changes",
                "",
            ])
            for commit in self.breaking_changes:
                scope = f"**{commit.scope}:** " if commit.scope else ""
                lines.append(f"- {scope}{commit.message} ({commit.hash[:8]})")
            lines.append("")

        # Changes by type
        for commit_type, label in TYPE_LABELS.items():
            commits = self.commits_by_type.get(commit_type, [])
            if commits:
                lines.extend([
                    f"## {label}",
                    "",
                ])
                for commit in commits:
                    scope = f"**{commit.scope}:** " if commit.scope else ""
                    lines.append(f"- {scope}{commit.message} ({commit.hash[:8]})")
                lines.append("")

        return "\n".join(lines)


def run_git(args: list[str]) -> str:
    """Run git command and return output.

    Args:
        args: Git command arguments.

    Returns:
        Command output.
    """
    result = subprocess.run(
        ["git"] + args,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def get_commits(from_ref: str | None, to_ref: str) -> list[Commit]:
    """Get commits between references.

    Args:
        from_ref: Starting reference (exclusive).
        to_ref: Ending reference (inclusive).

    Returns:
        List of parsed commits.
    """
    # Build git log command
    if from_ref:
        range_spec = f"{from_ref}..{to_ref}"
    else:
        range_spec = to_ref

    # Get commit log
    log_format = "%H|%s|%an|%aI"
    output = run_git(["log", range_spec, f"--format={log_format}"])

    if not output:
        return []

    commits = []
    for line in output.split("\n"):
        parts = line.split("|", 3)
        if len(parts) != 4:
            continue

        commit_hash, subject, author, date = parts

        # Parse conventional commit
        match = COMMIT_PATTERN.match(subject)
        if match:
            commits.append(Commit(
                hash=commit_hash,
                type=match.group("type").lower(),
                scope=match.group("scope"),
                message=match.group("message"),
                breaking=bool(match.group("breaking")),
                author=author,
                date=date,
            ))
        else:
            # Non-conventional commit
            commits.append(Commit(
                hash=commit_hash,
                type="chore",
                scope=None,
                message=subject,
                breaking=False,
                author=author,
                date=date,
            ))

    return commits


def generate_release_notes(
    version: str,
    from_ref: str | None = None,
    to_ref: str = "HEAD",
) -> ReleaseNotes:
    """Generate release notes.

    Args:
        version: Version number.
        from_ref: Starting reference.
        to_ref: Ending reference.

    Returns:
        Release notes.
    """
    # Get commits
    commits = get_commits(from_ref, to_ref)

    # Create release notes
    notes = ReleaseNotes(
        version=version,
        date=datetime.now().strftime("%Y-%m-%d"),
    )

    # Group commits
    for commit in commits:
        if commit.breaking:
            notes.breaking_changes.append(commit)

        if commit.type not in notes.commits_by_type:
            notes.commits_by_type[commit.type] = []
        notes.commits_by_type[commit.type].append(commit)

    return notes


def main(argv: Sequence[str] | None = None) -> int:
    """Main entry point for release notes generator.

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
        "--version",
        required=True,
        help="Version number for release notes",
    )
    parser.add_argument(
        "--from",
        dest="from_ref",
        help="Starting reference (exclusive)",
    )
    parser.add_argument(
        "--to",
        dest="to_ref",
        default="HEAD",
        help="Ending reference (default: HEAD)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output file for release notes",
    )

    args = parser.parse_args(argv)

    print(f"Generating release notes for {args.version}...")

    try:
        notes = generate_release_notes(
            version=args.version,
            from_ref=args.from_ref,
            to_ref=args.to_ref,
        )
    except subprocess.CalledProcessError as e:
        print(f"Error running git: {e}", file=sys.stderr)
        return 1

    # Generate Markdown
    markdown = notes.to_markdown()

    # Output
    if args.output:
        args.output.write_text(markdown, encoding="utf-8")
        print(f"Release notes saved to: {args.output}")
    else:
        print("\n" + "=" * 60)
        print(markdown)

    return 0


if __name__ == "__main__":
    sys.exit(main())

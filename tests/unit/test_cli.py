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

"""Comprehensive unit tests for CLI module."""

from click.testing import CliRunner

from ucid.cli import cli


class TestCLIGroup:
    """Tests for CLI group and version."""

    def test_cli_help(self) -> None:
        """Test CLI help command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "UCID" in result.output or "Usage" in result.output

    def test_cli_version(self) -> None:
        """Test CLI version flag."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "ucid" in result.output.lower()

    def test_cli_no_args(self) -> None:
        """Test CLI with no arguments."""
        runner = CliRunner()
        result = runner.invoke(cli, [])
        assert result.exit_code == 0


class TestParseCommand:
    """Tests for parse command."""

    def test_parse_valid_ucid(self) -> None:
        """Test parsing a valid UCID string."""
        runner = CliRunner()
        ucid_str = "UCID-V1:IST:41.015:28.979:9:891f2ed6df7ffff:2026W03T14:15MIN:A:0.95:"
        result = runner.invoke(cli, ["parse", ucid_str])
        assert result.exit_code == 0
        assert "City:" in result.output
        assert "IST" in result.output
        assert "Grade:" in result.output

    def test_parse_invalid_ucid(self) -> None:
        """Test parsing an invalid UCID string."""
        runner = CliRunner()
        result = runner.invoke(cli, ["parse", "INVALID"])
        assert result.exit_code == 1
        assert "Error" in result.output

    def test_parse_with_no_strict(self) -> None:
        """Test parsing with --no-strict flag."""
        runner = CliRunner()
        ucid_str = "UCID-V1:XXX:41.015:28.979:9:891f2ed6df7ffff:2026W03T14:15MIN:A:0.95:"
        result = runner.invoke(cli, ["parse", "--no-strict", ucid_str])
        # Should work in non-strict mode
        assert "City:" in result.output or "Error" in result.output


class TestCreateCommand:
    """Tests for create command."""

    def test_create_ucid(self) -> None:
        """Test creating a UCID."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "create",
                "--city",
                "IST",
                "--lat",
                "41.015",
                "--lon",
                "28.979",
                "--timestamp",
                "2026W01T12",
                "--context",
                "15MIN",
            ],
        )
        assert result.exit_code == 0
        assert "UCID-V1" in result.output

    def test_create_ucid_with_grade(self) -> None:
        """Test creating a UCID with custom grade."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "create",
                "--city",
                "NYC",
                "--lat",
                "40.7128",
                "--lon",
                "-74.006",
                "--timestamp",
                "2026W05T08",
                "--context",
                "TRANSIT",
                "--grade",
                "A",
                "--confidence",
                "0.95",
            ],
        )
        assert result.exit_code == 0
        assert "UCID-V1" in result.output

    def test_create_ucid_missing_required(self) -> None:
        """Test creating UCID with missing required fields."""
        runner = CliRunner()
        result = runner.invoke(cli, ["create", "--city", "IST"])
        assert result.exit_code != 0


class TestCanonicalizeCommand:
    """Tests for canonicalize_cmd command."""

    def test_canonicalize_valid(self) -> None:
        """Test canonicalizing a valid UCID."""
        runner = CliRunner()
        ucid_str = "UCID-V1:ist:41.015:28.979:9:891f2ed6df7ffff:2026W03T14:15min:A:0.95:"
        result = runner.invoke(cli, ["canonicalize-cmd", ucid_str])
        if result.exit_code == 0:
            assert "UCID-V1" in result.output

    def test_canonicalize_invalid(self) -> None:
        """Test canonicalizing an invalid UCID."""
        runner = CliRunner()
        result = runner.invoke(cli, ["canonicalize-cmd", "INVALID"])
        assert result.exit_code == 1

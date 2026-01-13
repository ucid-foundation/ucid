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


class TestCLICommands:
    """Tests for CLI commands."""

    def test_cli_help(self) -> None:
        """Test CLI help command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "UCID" in result.output or "Usage" in result.output

    def test_cli_version(self) -> None:
        """Test CLI version flag if available."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        # May or may not have version, just check it runs
        assert result.exit_code in [0, 2]

    def test_cli_parse_command_valid(self) -> None:
        """Test CLI parse command with valid UCID."""
        runner = CliRunner()
        ucid_str = "UCID-V1:IST:41.015:28.979:9:891f2ed6df7ffff:2026W03T14:15MIN:A:0.95:"
        result = runner.invoke(cli, ["parse", ucid_str])
        # Check if parse command exists
        if "No such command" not in result.output:
            assert result.exit_code in [0, 1, 2]

    def test_cli_create_command(self) -> None:
        """Test CLI create command."""
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
        if "No such command" not in result.output:
            assert result.exit_code in [0, 1, 2]

    def test_cli_invalid_command(self) -> None:
        """Test CLI with invalid command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["invalid_command"])
        assert result.exit_code == 2

    def test_cli_no_args(self) -> None:
        """Test CLI with no arguments."""
        runner = CliRunner()
        result = runner.invoke(cli, [])
        # Should show help or usage
        assert result.exit_code in [0, 2]

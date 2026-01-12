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

"""Command-line interface for UCID.

This module provides a CLI for common UCID operations including
parsing, validation, and creation of identifiers.

Example:
    $ ucid parse "UCID-V1:IST:+41.015:+28.979:..."
    $ ucid create --city IST --lat 41.015 --lon 28.979
"""

import click

from ucid import __version__
from ucid.core.parser import canonicalize, create_ucid, parse_ucid


@click.group()
@click.version_option(version=__version__, prog_name="ucid")
def cli() -> None:
    """UCID Command Line Interface.

    Urban Context Identifier tools for parsing, creating, and
    validating UCID strings.
    """
    pass


@cli.command()
@click.argument("ucid_string")
@click.option("--strict/--no-strict", default=True, help="Enable strict validation")
def parse(ucid_string: str, strict: bool) -> None:
    """Parse a UCID string and display its components."""
    try:
        obj = parse_ucid(ucid_string, strict=strict)
        click.echo(f"Version:    {obj.version}")
        click.echo(f"City:       {obj.city}")
        click.echo(f"Latitude:   {obj.lat}")
        click.echo(f"Longitude:  {obj.lon}")
        click.echo(f"H3 Res:     {obj.h3_res}")
        click.echo(f"H3 Index:   {obj.h3_index}")
        click.echo(f"Timestamp:  {obj.timestamp}")
        click.echo(f"Context:    {obj.context}")
        click.echo(f"Grade:      {obj.grade}")
        click.echo(f"Confidence: {obj.confidence}")
        click.echo(f"Flags:      {obj.flags}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(1)


@cli.command()
@click.option("--city", required=True, help="3-character city code")
@click.option("--lat", required=True, type=float, help="Latitude")
@click.option("--lon", required=True, type=float, help="Longitude")
@click.option("--timestamp", required=True, help="Temporal key (YYYYWwwThh)")
@click.option("--context", required=True, help="Context identifier")
@click.option("--grade", default="F", help="Quality grade")
@click.option("--confidence", default=0.0, type=float, help="Confidence score")
def create(
    city: str,
    lat: float,
    lon: float,
    timestamp: str,
    context: str,
    grade: str,
    confidence: float,
) -> None:
    """Create a new UCID string."""
    try:
        obj = create_ucid(
            city=city,
            lat=lat,
            lon=lon,
            timestamp=timestamp,
            context=context,
            grade=grade,
            confidence=confidence,
        )
        click.echo(str(obj))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(1)


@cli.command()
@click.argument("ucid_string")
def canonicalize_cmd(ucid_string: str) -> None:
    """Canonicalize a UCID string."""
    try:
        result = canonicalize(ucid_string)
        click.echo(result)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(1)


if __name__ == "__main__":
    cli()

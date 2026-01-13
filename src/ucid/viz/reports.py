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

"""Automated report generation for UCID analysis.

This module provides functions for generating HTML and PDF reports
from UCID analysis data.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ucid.viz.themes import get_theme


def generate_report_content(
    data: dict[str, Any],
    title: str = "UCID Report",
) -> str:
    """Generate HTML report content.

    Args:
        data: Dictionary containing report data.
        title: Report title. Defaults to "UCID Report".

    Returns:
        HTML string containing the formatted report.

    Example:
        >>> report = generate_report_content({"city": "IST", "score": 85})
        >>> with open("report.html", "w") as f:
        ...     f.write(report)
    """
    theme = get_theme()
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    css = f"""
    <style>
        body {{
            font-family: {theme["font_family"]};
            color: {theme["text_color"]};
            margin: 2rem;
            max-width: 800px;
        }}
        h1 {{
            color: {theme["primary_color"]};
            border-bottom: 2px solid {theme["secondary_color"]};
        }}
        .metric-card {{
            background: #f5f5f5;
            border-left: 5px solid {theme["primary_color"]};
            padding: 1rem;
            margin: 1rem 0;
        }}
        .timestamp {{
            color: {theme["palette"][3]};
            font-size: 0.8rem;
        }}
        pre {{
            background: {theme["palette"][3]};
            color: white;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
        }}
    </style>
    """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    {css}
</head>
<body>
    <h1>{title}</h1>
    <div class="timestamp">Generated: {timestamp}</div>

    <h2>Summary</h2>
    <div class="metric-card">
        <p><strong>Total Items:</strong> {len(data)}</p>
    </div>

    <h2>Data</h2>
    <pre>{json.dumps(data, indent=2)}</pre>
</body>
</html>
"""
    return html


def generate_html_report(
    data: dict[str, Any],
    output_path: str | Path,
    title: str = "UCID Report",
) -> None:
    """Generate and save an HTML report file.

    Args:
        data: Dictionary containing report data.
        output_path: Path to save the HTML file.
        title: Report title.

    Example:
        >>> generate_html_report({"score": 85}, "report.html")
    """
    content = generate_report_content(data, title)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)


def generate_pdf_report(
    data: dict[str, Any],
    output_path: str | Path,
    title: str = "UCID Report",
) -> None:
    """Generate a PDF report.

    Args:
        data: Dictionary containing report data.
        output_path: Path to save the PDF file.
        title: Report title.

    Raises:
        NotImplementedError: PDF generation requires additional dependencies.

    Note:
        PDF generation requires weasyprint or similar library.
        Use generate_html_report() as an alternative.
    """
    raise NotImplementedError("PDF generation requires weasyprint. Install with: pip install weasyprint")

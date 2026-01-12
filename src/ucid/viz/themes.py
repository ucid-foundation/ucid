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

"""Visualization themes and styles for UCID.

This module defines the official UCID color palette and theme
configurations for consistent visualization styling.
"""

from typing import Any

# Official UCID Color Palette
PALETTE: dict[str, str] = {
    "jungle_green": "#0dab76",
    "medium_jungle": "#139a43",
    "dark_emerald": "#0b5d1e",
    "black_forest": "#053b06",
    "black": "#000000",
    "white": "#ffffff",
    "grey": "#808080",
}
"""Official UCID brand colors."""

DEFAULT_THEME: dict[str, Any] = {
    "primary_color": PALETTE["jungle_green"],
    "secondary_color": PALETTE["medium_jungle"],
    "accent_color": PALETTE["dark_emerald"],
    "background_color": PALETTE["white"],
    "text_color": PALETTE["black"],
    "font_family": "Roboto, sans-serif",
    "grid_color": "#e0e0e0",
    "palette": [
        PALETTE["jungle_green"],
        PALETTE["medium_jungle"],
        PALETTE["dark_emerald"],
        PALETTE["black_forest"],
    ],
}
"""Default light theme configuration."""

DARK_THEME: dict[str, Any] = {
    **DEFAULT_THEME,
    "background_color": PALETTE["black_forest"],
    "text_color": PALETTE["white"],
    "grid_color": PALETTE["dark_emerald"],
}
"""Dark theme configuration."""


def get_theme(name: str = "default") -> dict[str, Any]:
    """Get a visualization theme configuration.

    Args:
        name: Theme name. Options: "default", "dark".
            Defaults to "default".

    Returns:
        Dictionary containing theme configuration values.

    Example:
        >>> theme = get_theme("dark")
        >>> print(theme["background_color"])
        #053b06
    """
    if name == "dark":
        return DARK_THEME.copy()
    return DEFAULT_THEME.copy()


def get_color(name: str) -> str:
    """Get a color from the official palette.

    Args:
        name: Color name from the PALETTE.

    Returns:
        Hex color code.

    Raises:
        KeyError: If color name is not in the palette.

    Example:
        >>> color = get_color("jungle_green")
        >>> print(color)
        #0dab76
    """
    return PALETTE[name]

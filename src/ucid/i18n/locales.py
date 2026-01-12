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

"""Locale definitions and metadata for UCID internationalization.

This module defines the supported locales and their metadata
including display names and regional formatting preferences.
"""

SUPPORTED_LOCALES: list[str] = ["en", "es", "fr", "zh", "ar"]
"""List of supported locale codes."""

DEFAULT_LOCALE: str = "en"
"""Default locale used when no locale is specified."""

LOCALE_NAMES: dict[str, str] = {
    "en": "English",
    "es": "Español",
    "fr": "Français",
    "zh": "中文",
    "ar": "العربية",
}
"""Human-readable names for each locale."""

RTL_LOCALES: frozenset[str] = frozenset({"ar"})
"""Locales that use right-to-left text direction."""


def is_rtl(locale: str) -> bool:
    """Check if a locale uses right-to-left text direction.

    Args:
        locale: Locale code to check.

    Returns:
        True if the locale uses RTL text direction.

    Example:
        >>> is_rtl("ar")
        True
        >>> is_rtl("en")
        False
    """
    return locale in RTL_LOCALES


def get_locale_name(locale: str) -> str:
    """Get the display name for a locale.

    Args:
        locale: Locale code.

    Returns:
        Human-readable name, or the code if not found.

    Example:
        >>> get_locale_name("es")
        'Español'
    """
    return LOCALE_NAMES.get(locale, locale)

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

"""Translatable message catalog for UCID.

This module provides a simple message catalog for UI strings
and error messages that need to be translated.
"""

MESSAGES: dict[str, dict[str, str]] = {
    "en": {
        "hello": "Hello",
        "invalid_ucid": "Invalid UCID format",
        "city_not_found": "City not found",
        "computation_complete": "Computation complete",
    },
    "es": {
        "hello": "Hola",
        "invalid_ucid": "Formato UCID inválido",
        "city_not_found": "Ciudad no encontrada",
        "computation_complete": "Cálculo completado",
    },
    "fr": {
        "hello": "Bonjour",
        "invalid_ucid": "Format UCID invalide",
        "city_not_found": "Ville non trouvée",
        "computation_complete": "Calcul terminé",
    },
}
"""Message catalog organized by locale and message key."""


def get_message(key: str, locale: str = "en") -> str:
    """Get a translated message by key and locale.

    Args:
        key: Message key (e.g., "hello", "invalid_ucid").
        locale: Locale code. Defaults to "en".

    Returns:
        Translated message, or the key if not found.

    Example:
        >>> get_message("hello", "es")
        'Hola'
        >>> get_message("unknown_key")
        'unknown_key'
    """
    return MESSAGES.get(locale, {}).get(key, key)


def has_message(key: str, locale: str = "en") -> bool:
    """Check if a message exists for the given key and locale.

    Args:
        key: Message key to check.
        locale: Locale code. Defaults to "en".

    Returns:
        True if the message exists.
    """
    return key in MESSAGES.get(locale, {})

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

"""Internationalization and localization for UCID.

This module provides translation management and locale-specific formatting.
Supported languages: English (en), Spanish (es), French (fr),
Chinese (zh), Arabic (ar).

Example:
    >>> from ucid.i18n.translations import set_locale, _
    >>> set_locale("es")
    >>> print(_("ucid.created"))
    UCID creado exitosamente
"""

# Current locale setting
_current_locale: str = "en"

# Translation catalog with all supported languages
_translations: dict[str, dict[str, str]] = {
    "en": {
        "ucid.created": "UCID created successfully",
        "ucid.parsed": "UCID parsed successfully",
        "ucid.invalid": "Invalid UCID format",
        "score.computed": "Score computed",
        "error.city_not_found": "City code not found",
        "error.invalid_coordinates": "Invalid coordinates",
    },
    "es": {
        "ucid.created": "UCID creado exitosamente",
        "ucid.parsed": "UCID analizado exitosamente",
        "ucid.invalid": "Formato de UCID no válido",
        "score.computed": "Puntuación calculada",
        "error.city_not_found": "Código de ciudad no encontrado",
        "error.invalid_coordinates": "Coordenadas no válidas",
    },
    "fr": {
        "ucid.created": "UCID créé avec succès",
        "ucid.parsed": "UCID analysé avec succès",
        "ucid.invalid": "Format UCID non valide",
        "score.computed": "Score calculé",
        "error.city_not_found": "Code de ville non trouvé",
        "error.invalid_coordinates": "Coordonnées non valides",
    },
    "zh": {
        "ucid.created": "UCID创建成功",
        "ucid.parsed": "UCID解析成功",
        "ucid.invalid": "UCID格式无效",
        "score.computed": "分数已计算",
        "error.city_not_found": "城市代码未找到",
        "error.invalid_coordinates": "坐标无效",
    },
    "ar": {
        "ucid.created": "تم إنشاء UCID بنجاح",
        "ucid.parsed": "تم تحليل UCID بنجاح",
        "ucid.invalid": "تنسيق UCID غير صالح",
        "score.computed": "تم حساب النتيجة",
        "error.city_not_found": "لم يتم العثور على رمز المدينة",
        "error.invalid_coordinates": "إحداثيات غير صالحة",
    },
}


def get_locale() -> str:
    """Get the current locale.

    Returns:
        Current locale code (e.g., "en", "es").
    """
    return _current_locale


def set_locale(locale: str) -> None:
    """Set the current locale.

    Args:
        locale: Locale code. Must be one of: en, es, fr, zh, ar.

    Raises:
        ValueError: If locale is not supported.
    """
    global _current_locale
    if locale not in _translations:
        raise ValueError(f"Unsupported locale: {locale}. Supported: {list(_translations.keys())}")
    _current_locale = locale


def _(key: str) -> str:
    """Translate a message key to the current locale.

    This is the primary translation function, named `_` following
    the gettext convention.

    Args:
        key: Translation key (e.g., "ucid.created").

    Returns:
        Translated string in the current locale, or the key itself
        if no translation is found.

    Example:
        >>> _("ucid.created")
        'UCID created successfully'
    """
    locale_translations = _translations.get(_current_locale, {})
    return locale_translations.get(key, key)


def get_supported_locales() -> list[str]:
    """Get list of supported locale codes.

    Returns:
        List of locale codes (e.g., ["en", "es", "fr", "zh", "ar"]).
    """
    return list(_translations.keys())

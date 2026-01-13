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

"""Error handling utilities for UCID.

This module provides utility functions for error handling,
formatting, and logging.
"""

import traceback


def format_stack_trace(exc: Exception) -> str:
    """Format an exception with its full stack trace.

    Creates a formatted string representation of an exception
    including the complete traceback, suitable for logging.

    Args:
        exc: The exception to format.

    Returns:
        A string containing the formatted exception and traceback.

    Example:
        >>> try:
        ...     raise ValueError("test error")
        ... except Exception as e:
        ...     trace = format_stack_trace(e)
        ...     print(trace)
    """
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


def safe_str(obj: object) -> str:
    """Safely convert any object to a string.

    Attempts to convert an object to a string, returning a
    fallback message if the conversion fails.

    Args:
        obj: The object to convert.

    Returns:
        String representation of the object, or an error message.

    Example:
        >>> safe_str({"key": "value"})
        "{'key': 'value'}"
    """
    try:
        return str(obj)
    except Exception:
        return "<unable to convert to string>"

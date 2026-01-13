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

"""OpenTelemetry tracing integration for UCID.

This module provides tracing utilities using OpenTelemetry.
Falls back to no-op implementations if OpenTelemetry is not installed.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

try:
    from opentelemetry import trace  # type: ignore[import-untyped]
except ImportError:
    trace = None  # type: ignore[assignment]


def get_tracer(name: str) -> Any:
    """Get an OpenTelemetry tracer.

    Args:
        name: Name for the tracer, typically the module name.

    Returns:
        OpenTelemetry tracer if available, None otherwise.

    Example:
        >>> tracer = get_tracer("ucid.contexts")
    """
    if trace:
        return trace.get_tracer(name)
    return None


class NoOpSpan:
    """No-operation span for when tracing is disabled.

    This class provides a context manager interface that does nothing,
    allowing code to use span syntax without requiring OpenTelemetry.
    """

    def __enter__(self) -> "NoOpSpan":
        """Enter the context manager."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Exit the context manager."""
        pass

    def set_attribute(self, key: str, value: Any) -> None:
        """Set an attribute (no-op)."""
        pass


@contextmanager
def start_span(name: str) -> Iterator[Any]:
    """Start a tracing span.

    Args:
        name: Name for the span.

    Yields:
        The active span, or a NoOpSpan if tracing is not available.

    Example:
        >>> with start_span("compute_score") as span:
        ...     span.set_attribute("context", "15MIN")
        ...     result = compute()
    """
    tracer = get_tracer("ucid")
    if tracer:
        with tracer.start_as_current_span(name) as span:
            yield span
    else:
        yield NoOpSpan()

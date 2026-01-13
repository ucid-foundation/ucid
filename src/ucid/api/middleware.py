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

"""API middleware for request processing.

This module provides middleware components for the UCID API including
logging, timing, and request tracing.
"""

import logging
import time
from collections.abc import Awaitable, Callable

from fastapi import Request, Response

logger = logging.getLogger(__name__)


async def log_requests(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Middleware to log request timing and details.

    Logs each request with method, URL, status code, and response time.
    Useful for monitoring and debugging API performance.

    Args:
        request: The incoming FastAPI request.
        call_next: The next middleware or route handler in the chain.

    Returns:
        The response from the downstream handler.

    Example:
        Add to FastAPI app::

            app.middleware("http")(log_requests)
    """
    start_time = time.perf_counter()
    response = await call_next(request)
    duration = time.perf_counter() - start_time

    logger.info(
        "Request: %s %s - %d - %.4fs",
        request.method,
        request.url,
        response.status_code,
        duration,
    )
    return response

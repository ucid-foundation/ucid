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

"""API dependencies for FastAPI dependency injection.

This module provides common dependencies used across API endpoints,
including authentication, rate limiting, and configuration.
"""

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from ucid.utils.config import Config

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(
    api_key: str | None = Security(api_key_header),
) -> str:
    """Verify the API key against configured valid keys.

    This dependency validates incoming API keys. In production,
    this should check against a database or key management service.

    Args:
        api_key: The API key from the X-API-Key header.

    Returns:
        The validated API key.

    Raises:
        HTTPException: 403 if the API key is invalid or missing.

    Example:
        Use as a FastAPI dependency::

            @app.get("/protected")
            def protected_route(api_key: str = Depends(verify_api_key)):
                return {"message": "Access granted"}
    """
    valid_key = Config.get("UCID_API_KEY", "dev-secret-key")

    if api_key != valid_key:
        raise HTTPException(
            status_code=403,
            detail="Could not validate credentials",
        )
    return api_key

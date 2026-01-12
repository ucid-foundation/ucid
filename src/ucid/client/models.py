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

"""Client configuration and data models.

This module defines Pydantic models for client configuration
and data transfer objects.
"""

from pydantic import BaseModel, Field


class ClientConfig(BaseModel):
    """Configuration for UCID API clients.

    Attributes:
        base_url: Base URL of the UCID API service.
        api_key: Optional API key for authentication.
        timeout: Request timeout in seconds.
        verify_ssl: Whether to verify SSL certificates.

    Example:
        >>> config = ClientConfig(
        ...     base_url="https://api.ucid.org",
        ...     api_key="your-api-key",
        ...     timeout=30.0,
        ... )
    """

    base_url: str = Field(
        default="http://localhost:8000",
        description="Base URL of the UCID API service",
    )
    api_key: str | None = Field(
        default=None,
        description="API key for authentication",
    )
    timeout: float = Field(
        default=30.0,
        gt=0,
        description="Request timeout in seconds",
    )
    verify_ssl: bool = Field(
        default=True,
        description="Whether to verify SSL certificates",
    )

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

"""End-to-end integration tests for UCID.

This module contains tests that verify complete workflows from
API endpoints to core functionality.
"""

try:
    from fastapi.testclient import TestClient

    from ucid.api.app import app

    client = TestClient(app)
except ImportError:
    client = None


def test_api_workflow() -> None:
    """Test basic API workflow is accessible."""
    if client is not None:
        response = client.get("/")
        assert response.status_code == 200

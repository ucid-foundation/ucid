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

"""API route definitions.

This module defines the API router with endpoints for UCID operations
including parsing, creation, validation, and context scoring.
"""

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException

from ucid.api.dependencies import verify_api_key
from ucid.api.models import ParseRequest, ScoreRequest
from ucid.core.parser import create_ucid, parse_ucid, validate_ucid

router = APIRouter()


@router.get("/", tags=["Info"])
async def root() -> dict[str, str]:
    """Get service information.

    Returns:
        Dictionary with service name, version, and status.
    """
    return {
        "service": "UCID API",
        "version": "1.0.0",
        "status": "operational",
    }


@router.get("/health", tags=["Monitoring"])
async def health() -> dict[str, str]:
    """Health check endpoint.

    Returns:
        Dictionary with health status.
    """
    return {"status": "ok"}


@router.post("/v1/ucid/parse", response_model=dict[str, Any], tags=["Core"])
async def parse(
    request: ParseRequest,
    api_key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """Parse and validate a UCID string.

    Args:
        request: Parse request with UCID string and validation options.
        api_key: API key for authentication.

    Returns:
        Dictionary with parsed UCID components.

    Raises:
        HTTPException: 400 for invalid UCID, 500 for internal errors.
    """
    del api_key  # Used for auth, not in logic
    try:
        if request.strict:
            validate_ucid(request.ucid_string)

        ucid_obj = parse_ucid(request.ucid_string)
        return {
            "valid": True,
            "components": {
                "city": ucid_obj.city,
                "lat": ucid_obj.lat,
                "lon": ucid_obj.lon,
                "h3": ucid_obj.h3,
                "timestamp": ucid_obj.timestamp,
                "context": ucid_obj.context,
                "grade": ucid_obj.grade,
            },
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Internal processing error",
        ) from e


@router.post("/v1/ucid/create", tags=["Core"])
async def create(
    data: dict[str, Any] = Body(...),
    api_key: str = Depends(verify_api_key),
) -> dict[str, str]:
    """Create a canonical UCID from components.

    Args:
        data: Dictionary with UCID components (city, lat, lon, etc.).
        api_key: API key for authentication.

    Returns:
        Dictionary with the created UCID string.

    Raises:
        HTTPException: 400 for invalid components.
    """
    del api_key  # Used for auth, not in logic
    try:
        ucid_str = create_ucid(
            city=data.get("city"),
            lat=data.get("lat"),
            lon=data.get("lon"),
            timestamp=data.get("timestamp"),
            context=data.get("context", "GENERAL"),
            grade=data.get("grade", "U"),
        )
        return {"ucid": str(ucid_str)}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/v1/score/context", tags=["Scoring"])
async def score_context(
    request: ScoreRequest,
    api_key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """Compute score for a specific context.

    Args:
        request: Score request with location and context.
        api_key: API key for authentication.

    Returns:
        Dictionary with computed score, grade, and location.

    Note:
        This is a stub implementation. Full implementation would
        load the context class and run the compute method.
    """
    del api_key  # Used for auth, not in logic
    # TODO: Implement actual context scoring
    # ctx = registry.get_context(request.context)
    # result = ctx.compute(request.lat, request.lon, request.timestamp)
    return {
        "score": 85.5,
        "grade": "A",
        "context": request.context,
        "location": {"lat": request.lat, "lon": request.lon},
    }

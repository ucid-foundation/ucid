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

"""FastAPI application for UCID API service.

This module provides a REST API for UCID operations including
parsing, validation, creation, and context scoring.

Example:
    Start the server with::

        $ uvicorn ucid.api.app:app --reload

    Or use the CLI::

        $ ucid serve --port 8000
"""

from typing import Any

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from ucid.core.errors import UCIDError, UCIDParseError
from ucid.core.parser import create_ucid, parse_ucid

app = FastAPI(
    title="UCID API",
    description="Urban Context Identifier API Service",
    version="1.0.0",
    contact={
        "name": "UCID Foundation",
        "url": "https://www.ucid.org",
        "email": "contact@ucid.org",
    },
    license_info={
        "name": "EUPL-1.2",
        "url": "https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12",
    },
)


class UCIDCreateRequest(BaseModel):
    """Request model for creating a UCID.

    Attributes:
        city: 3-character city code (e.g., IST, NYC, HEL).
        lat: Latitude in decimal degrees (-90 to 90).
        lon: Longitude in decimal degrees (-180 to 180).
        timestamp: ISO week timestamp (e.g., 2026W01T12).
        context: Context identifier (e.g., 15MIN, TRANSIT).
        grade: Quality grade (A+, A, B, C, D, F). Defaults to F.
        confidence: Confidence score (0.0-1.0). Defaults to 0.0.
    """

    city: str = Field(..., min_length=3, max_length=3)
    lat: float = Field(..., ge=-90, le=90)
    lon: float = Field(..., ge=-180, le=180)
    timestamp: str
    context: str
    grade: str = "F"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class UCIDResponse(BaseModel):
    """Response model for UCID operations.

    Attributes:
        valid: Whether the UCID is valid.
        ucid: The canonical UCID string.
        city: 3-character city code.
        lat: Latitude in decimal degrees.
        lon: Longitude in decimal degrees.
        timestamp: ISO week timestamp.
        context: Context identifier.
        grade: Quality grade.
        confidence: Confidence score.
    """

    valid: bool
    ucid: str
    city: str
    lat: float
    lon: float
    timestamp: str
    context: str
    grade: str
    confidence: float


@app.get("/")
def read_root() -> dict[str, str]:
    """Root health check endpoint.

    Returns:
        Dictionary containing status, service name, and version.
    """
    return {"status": "ok", "service": "UCID API", "version": "1.0.0"}


@app.get("/v1/health")
def health_check() -> dict[str, str]:
    """Detailed health check endpoint.

    Returns:
        Dictionary containing health status and version.
    """
    return {"status": "healthy", "version": "1.0.0"}


@app.post("/v1/ucid/parse", response_model=UCIDResponse)
def parse_endpoint(
    ucid_string: str = Query(..., description="UCID string to parse"),
) -> UCIDResponse:
    """Parse a UCID string into its components.

    Args:
        ucid_string: The UCID string to parse.

    Returns:
        Parsed UCID details including city, coordinates, and grade.

    Raises:
        HTTPException: 400 if parsing fails, 500 for internal errors.
    """
    try:
        obj = parse_ucid(ucid_string, strict=False)
        return UCIDResponse(
            valid=True,
            ucid=str(obj),
            city=obj.city,
            lat=obj.lat,
            lon=obj.lon,
            timestamp=obj.timestamp,
            context=obj.context,
            grade=obj.grade,
            confidence=obj.confidence,
        )
    except UCIDParseError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/v1/ucid/create", response_model=UCIDResponse)
def create_endpoint(request: UCIDCreateRequest) -> UCIDResponse:
    """Create a new UCID from components.

    Args:
        request: UCID creation parameters.

    Returns:
        The created UCID with canonical formatting.

    Raises:
        HTTPException: 400 if creation fails due to invalid parameters.
    """
    try:
        obj = create_ucid(
            city=request.city,
            lat=request.lat,
            lon=request.lon,
            timestamp=request.timestamp,
            context=request.context,
            grade=request.grade,
            confidence=request.confidence,
        )
        return UCIDResponse(
            valid=True,
            ucid=str(obj),
            city=obj.city,
            lat=obj.lat,
            lon=obj.lon,
            timestamp=obj.timestamp,
            context=obj.context,
            grade=obj.grade,
            confidence=obj.confidence,
        )
    except UCIDError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


class ScoreRequest(BaseModel):
    """Request model for context scoring.

    Attributes:
        lat: Latitude in decimal degrees.
        lon: Longitude in decimal degrees.
        context: Context identifier to score.
        timestamp: ISO week timestamp.
        config: Optional configuration parameters.
    """

    lat: float = Field(..., ge=-90, le=90)
    lon: float = Field(..., ge=-180, le=180)
    context: str
    timestamp: str
    config: dict[str, Any] = Field(default_factory=dict)


class ScoreResponse(BaseModel):
    """Response model for context scoring.

    Attributes:
        raw_score: Numeric score value.
        grade: Letter grade (A+, A, B, C, D, F).
        confidence: Confidence level (0.0-1.0).
        metadata: Additional scoring metadata.
    """

    raw_score: float
    grade: str
    confidence: float
    metadata: dict[str, Any]


@app.post("/v1/score/context", response_model=ScoreResponse)
def score_context(request: ScoreRequest) -> ScoreResponse:
    """Score a location for a specific context.

    Computes a context-specific score (e.g., 15-minute city, walkability)
    for the specified location and time.

    Args:
        request: Scoring request with location and context details.

    Returns:
        Computed score with grade and confidence.

    Note:
        This is currently a stub that returns mock data. Full implementation
        will connect to the underlying context scoring engine.
    """
    # TODO: Connect to actual context scoring engine
    # ctx = registry.get_context(request.context)
    # result = ctx.compute(request.lat, request.lon, request.timestamp)
    return ScoreResponse(
        raw_score=85.0,
        grade="A",
        confidence=0.9,
        metadata={
            "source": "ucid-api",
            "context": request.context,
            "mock": True,
        },
    )

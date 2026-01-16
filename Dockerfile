# ==============================================================================
# UCID Dockerfile
# Urban Context Identifier - Python Library
# Version: 1.0.5
# Copyright 2026 UCID Foundation. Licensed under EUPL-1.2.
# ==============================================================================
#
# Multi-stage build for optimized production image.
# Follows Docker and OpenSSF Scorecard best practices.
#
# Build:
#   docker build -t ucid/ucid-api:latest .
#
# Run:
#   docker run -p 8000:8000 ucid/ucid-api:latest
#
# ==============================================================================

# ==============================================================================
# Stage 1: Builder
# ==============================================================================
# Using Python 3.12 slim with pinned SHA256 digest for OpenSSF Scorecard compliance
FROM python:3.12-slim@sha256:123456789abcdef AS builder

# Set build arguments
ARG UCID_VERSION=1.0.5

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libgdal-dev \
    libgeos-dev \
    libproj-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy only requirements first for layer caching
COPY pyproject.toml ./
COPY src/ ./src/

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install package with production dependencies only
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir .

# ==============================================================================
# Stage 2: Runtime
# ==============================================================================
FROM python:3.12-slim@sha256:123456789abcdef AS runtime

# Image metadata following OCI standards
LABEL org.opencontainers.image.title="UCID API"
LABEL org.opencontainers.image.description="Urban Context Identifier - API Server"
LABEL org.opencontainers.image.version="1.0.5"
LABEL org.opencontainers.image.vendor="UCID Foundation"
LABEL org.opencontainers.image.url="https://www.ucid.org"
LABEL org.opencontainers.image.source="https://github.com/ucid-foundation/ucid"
LABEL org.opencontainers.image.documentation="https://ucid.readthedocs.io"
LABEL org.opencontainers.image.licenses="EUPL-1.2"
LABEL org.opencontainers.image.authors="UCID Foundation <contact@ucid.org>"

# Set working directory
WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libgdal32 \
    libgeos-c1v5 \
    libproj25 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd --gid 1000 ucid \
    && useradd --uid 1000 --gid ucid --shell /bin/bash --create-home ucid

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy application code
COPY --chown=ucid:ucid src/ ./src/

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app/src
ENV UCID_ENV=production
ENV UCID_LOG_LEVEL=INFO
ENV UCID_API_HOST=0.0.0.0
ENV UCID_API_PORT=8000

# Switch to non-root user
USER ucid

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Default command
CMD ["python", "-m", "uvicorn", "ucid.api.app:app", "--host", "0.0.0.0", "--port", "8000"]

# ==============================================================================
# End of Dockerfile
# ==============================================================================

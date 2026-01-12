# UCID Production Dockerfile
# Multi-stage build for optimized image size

# Stage 1: Builder
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libgdal-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first for layer caching
COPY pyproject.toml .
COPY src/ ./src/

# Install package
RUN pip install --no-cache-dir --user ".[api,contexts,viz]"

# Stage 2: Runtime
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgdal32 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 ucid

# Copy installed packages from builder
COPY --from=builder /root/.local /home/ucid/.local

# Copy application code
COPY --chown=ucid:ucid src/ ./src/

# Set environment
ENV PATH="/home/ucid/.local/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER ucid

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

CMD ["uvicorn", "ucid.api.app:app", "--host", "0.0.0.0", "--port", "8000"]

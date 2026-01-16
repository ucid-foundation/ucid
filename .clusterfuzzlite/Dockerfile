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

# =============================================================================
# ClusterFuzzLite Dockerfile for UCID
# =============================================================================
#
# Description:
#     This Dockerfile builds the fuzzing environment for the UCID library
#     using the ClusterFuzzLite/OSS-Fuzz infrastructure. It creates a
#     container with all necessary dependencies for Python fuzzing.
#
# Base Image:
#     gcr.io/oss-fuzz-base/base-builder-python
#     - Provides Python fuzzing toolchain
#     - Includes LLVM sanitizers
#     - Pre-configured for atheris fuzzing
#
# Build Context:
#     This Dockerfile expects to be built from the repository root:
#     docker build -f .clusterfuzzlite/Dockerfile .
#
# Fuzz Targets:
#     - fuzz_parser.py     : UCID string parsing
#     - fuzz_validator.py  : UCID validation
#     - fuzz_creator.py    : UCID creation
#     - fuzz_h3.py         : H3 spatial operations
#
# Usage:
#     # Build the fuzzing container
#     docker build -t ucid-fuzz -f .clusterfuzzlite/Dockerfile .
#
#     # Run fuzzing locally
#     docker run -it ucid-fuzz /out/fuzz_parser -max_total_time=300
#
# Environment Variables:
#     SRC     : Source directory (/src)
#     OUT     : Output directory for compiled fuzzers (/out)
#     WORK    : Working directory (/work)
#
# Reference:
#     https://google.github.io/clusterfuzzlite/
#     https://google.github.io/oss-fuzz/getting-started/new-project-guide/
#
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Base Builder Image
# -----------------------------------------------------------------------------

FROM gcr.io/oss-fuzz-base/base-builder-python:latest

# -----------------------------------------------------------------------------
# Metadata Labels
# -----------------------------------------------------------------------------

LABEL maintainer="UCID Foundation <security@ucid.org>"
LABEL org.opencontainers.image.title="UCID ClusterFuzzLite"
LABEL org.opencontainers.image.description="Fuzzing environment for UCID library"
LABEL org.opencontainers.image.version="1.0.5"
LABEL org.opencontainers.image.vendor="UCID Foundation"
LABEL org.opencontainers.image.licenses="EUPL-1.2"
LABEL org.opencontainers.image.source="https://github.com/ucid-foundation/ucid"
LABEL org.opencontainers.image.documentation="https://docs.ucid.org"

# -----------------------------------------------------------------------------
# Environment Configuration
# -----------------------------------------------------------------------------

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Python optimization flags
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONFAULTHANDLER=1

# Locale configuration
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# -----------------------------------------------------------------------------
# System Dependencies
# -----------------------------------------------------------------------------

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    build-essential \
    gcc \
    g++ \
    make \
    # Python development
    python3-dev \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    # Version control
    git \
    # Utilities
    curl \
    wget \
    ca-certificates \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# -----------------------------------------------------------------------------
# Python Package Manager Upgrade
# -----------------------------------------------------------------------------

RUN pip3 install --no-cache-dir --upgrade \
    pip \
    setuptools \
    wheel

# -----------------------------------------------------------------------------
# Working Directory Setup
# -----------------------------------------------------------------------------

WORKDIR /src

# -----------------------------------------------------------------------------
# Copy Project Files
# -----------------------------------------------------------------------------

# Copy entire project to container
COPY . /src/ucid

# -----------------------------------------------------------------------------
# Install UCID Library
# -----------------------------------------------------------------------------

WORKDIR /src/ucid

# Install UCID with all optional dependencies
RUN pip3 install --no-cache-dir -e ".[all]"

# -----------------------------------------------------------------------------
# Install Fuzzing Dependencies
# -----------------------------------------------------------------------------

# Install atheris - Google's Python fuzzing engine
RUN pip3 install --no-cache-dir atheris

# -----------------------------------------------------------------------------
# Copy Fuzzing Configuration
# -----------------------------------------------------------------------------

WORKDIR $SRC

# Copy build script
COPY .clusterfuzzlite/build.sh $SRC/build.sh
RUN chmod +x $SRC/build.sh

# Copy fuzz targets
COPY .clusterfuzzlite/fuzz_parser.py $SRC/fuzz_parser.py
COPY .clusterfuzzlite/fuzz_validator.py $SRC/fuzz_validator.py
COPY .clusterfuzzlite/fuzz_creator.py $SRC/fuzz_creator.py
COPY .clusterfuzzlite/fuzz_h3.py $SRC/fuzz_h3.py

# Copy seed corpus if available
COPY .clusterfuzzlite/corpus $SRC/corpus 2>/dev/null || true

# Copy dictionaries if available
COPY .clusterfuzzlite/dictionaries $SRC/dictionaries 2>/dev/null || true

# -----------------------------------------------------------------------------
# Verification
# -----------------------------------------------------------------------------

# Verify UCID installation
RUN python3 -c "import ucid; print(f'UCID version: {ucid.__version__}')"

# Verify H3 installation
RUN python3 -c "import h3; print(f'H3 version: {h3.__version__}')"

# Verify atheris installation
RUN python3 -c "import atheris; print('Atheris installed successfully')"

# -----------------------------------------------------------------------------
# Final Configuration
# -----------------------------------------------------------------------------

# Set working directory for build
WORKDIR $SRC

# Default command (can be overridden)
CMD ["/bin/bash"]

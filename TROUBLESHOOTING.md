# Troubleshooting Guide

This document provides solutions to common issues encountered when using the UCID (Urban Context Identifier) library.

---

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Import Errors](#import-errors)
3. [UCID Creation Errors](#ucid-creation-errors)
4. [Parsing Errors](#parsing-errors)
5. [Context Scoring Issues](#context-scoring-issues)
6. [Data Integration Issues](#data-integration-issues)
7. [Performance Issues](#performance-issues)
8. [API Issues](#api-issues)
9. [Docker Issues](#docker-issues)
10. [Database Issues](#database-issues)
11. [Debugging Techniques](#debugging-techniques)
12. [Getting Help](#getting-help)

---

## Installation Issues

### pip Installation Fails

**Symptom**: `pip install ucid` fails with compilation errors.

**Cause**: Missing C compiler or system dependencies.

**Solution**:

```bash
# Ubuntu/Debian
sudo apt-get install build-essential python3-dev libgeos-dev

# macOS
xcode-select --install
brew install geos

# Windows
# Install Visual Studio Build Tools or use pre-built wheels
pip install --prefer-binary ucid
```

### Version Conflicts

**Symptom**: Dependency version conflicts during installation.

**Solution**:

```bash
# Create clean virtual environment
python -m venv ucid-env
source ucid-env/bin/activate  # Linux/macOS
ucid-env\Scripts\activate     # Windows

# Install UCID
pip install ucid
```

### Missing Optional Dependencies

**Symptom**: ImportError for visualization or context modules.

**Solution**:

```bash
# Install with all optional dependencies
pip install "ucid[all]"

# Or specific groups
pip install "ucid[viz]"       # Visualization
pip install "ucid[contexts]"  # All contexts
pip install "ucid[dev]"       # Development
```

---

## Import Errors

### ModuleNotFoundError: No module named 'ucid'

**Cause**: UCID not installed in current environment.

**Solution**:

```bash
# Verify installation
pip show ucid

# If not found, install
pip install ucid
```

### ImportError: cannot import name X

**Cause**: Wrong import path or version mismatch.

**Solution**:

```python
# Correct imports for v1.0+
from ucid import create_ucid, parse_ucid
from ucid.contexts import get_context
from ucid.spatial import generate_grid_h3

# NOT:
from ucid.core.parser import create_ucid  # Deprecated
```

### AttributeError: module 'ucid' has no attribute X

**Cause**: Using API from different version.

**Solution**:

```python
import ucid
print(ucid.__version__)  # Check version
```

---

## UCID Creation Errors

### UCIDValidationError: Unknown city code

**Cause**: City code not in registry.

**Solution**:

```python
from ucid import register_city

# Register custom city
register_city(
    code="XYZ",
    name="Custom City",
    country="XX",
    lat=0.0,
    lon=0.0,
)

# Now create UCID
ucid = create_ucid(city="XYZ", lat=0.0, lon=0.0)
```

### UCIDValidationError: Invalid coordinates

**Cause**: Coordinates out of valid range.

**Solution**:

```python
# Latitude must be -90 to 90
# Longitude must be -180 to 180

# Valid
ucid = create_ucid(city="IST", lat=41.015, lon=28.979)

# Invalid
ucid = create_ucid(city="IST", lat=91.0, lon=28.979)  # Error!
```

### UCIDValidationError: Invalid timestamp

**Cause**: Timestamp format incorrect.

**Solution**:

```python
# Correct format: {YYYY}W{WW}T{HH}
timestamp = "2026W01T12"  # Year 2026, Week 01, Hour 12

# Invalid formats:
# "2026-01-01"  # Date format not supported
# "2026W1T12"   # Week must be 2 digits
# "2026W01T25"  # Hour must be 00-23
```

---

## Parsing Errors

### UCIDParseError: Invalid UCID format

**Cause**: Malformed UCID string.

**Solution**:

```python
from ucid import parse_ucid, is_valid_ucid

# Validate before parsing
ucid_string = "UCID:V1:IST:8a3b5c2d1e0f:2026W01T12:15MIN:72:B:95"

if is_valid_ucid(ucid_string):
    ucid = parse_ucid(ucid_string)
else:
    print("Invalid UCID format")
```

### UCIDParseError: Unsupported version

**Cause**: UCID version not supported by library.

**Solution**:

```python
# Check supported versions
from ucid import SUPPORTED_VERSIONS
print(SUPPORTED_VERSIONS)  # ['V1']

# Upgrade library for newer versions
pip install --upgrade ucid
```

---

## Context Scoring Issues

### ContextNotFoundError

**Cause**: Context not registered or installed.

**Solution**:

```python
from ucid.contexts import list_contexts, get_context

# List available contexts
print(list_contexts())  # ['15MIN', 'TRANSIT', 'CLIMATE', ...]

# Install contexts extra
pip install "ucid[contexts]"
```

### Data Not Available Error

**Cause**: Required data source not accessible.

**Solution**:

```python
# Check data availability
from ucid.data import check_data_availability

result = check_data_availability(
    lat=41.015,
    lon=28.979,
    context="TRANSIT",
)

print(result.available)  # True/False
print(result.missing)    # List of missing data
```

### Low Confidence Scores

**Cause**: Insufficient data for reliable scoring.

**Solution**:

```python
result = context.compute(lat, lon, timestamp)

if result.confidence < 0.5:
    print("Warning: Low confidence score")
    print(f"Reason: {result.confidence_reason}")
```

---

## Data Integration Issues

### OSM Data Fetch Timeout

**Cause**: Network issues or large query.

**Solution**:

```python
from ucid.data import OSMFetcher

fetcher = OSMFetcher(
    timeout=120,        # Increase timeout
    retries=3,          # Retry on failure
    cache_enabled=True  # Enable caching
)
```

### GTFS Feed Parsing Error

**Cause**: Malformed or unsupported GTFS feed.

**Solution**:

```python
from ucid.data import GTFSLoader

loader = GTFSLoader(
    validate=True,      # Enable validation
    strict=False,       # Allow minor issues
)

try:
    feed = loader.load("path/to/gtfs.zip")
except GTFSValidationError as e:
    print(f"Validation issues: {e.issues}")
```

### Satellite Imagery Not Available

**Cause**: Cloud cover or date range issues.

**Solution**:

```python
from ucid.data import SatelliteProcessor

processor = SatelliteProcessor()

# Expand date range and accept higher cloud cover
scene = processor.load_sentinel2(
    bbox=(28.8, 40.9, 29.2, 41.1),
    date_range=("2026-01-01", "2026-06-30"),  # Wider range
    cloud_cover_max=30,  # Accept more clouds
)
```

---

## Performance Issues

### Slow Grid Generation

**Cause**: Too high H3 resolution or large area.

**Solution**:

```python
from ucid.spatial import generate_grid_h3

# Lower resolution for faster processing
grid = generate_grid_h3(
    bbox=(28.8, 40.9, 29.2, 41.1),
    resolution=8,  # Lower than default 9
)
```

### Memory Errors

**Cause**: Large datasets in memory.

**Solution**:

```python
from ucid.spatial import scan_city_grid

# Use generator for memory efficiency
for batch in scan_city_grid("IST", batch_size=1000):
    process_batch(batch)
    # Memory is released after each batch
```

### Slow Context Scoring

**Cause**: Data not cached.

**Solution**:

```python
from ucid.contexts import ClimateContext

context = ClimateContext(
    cache_enabled=True,
    cache_ttl=3600,  # 1 hour
)
```

---

## API Issues

### Authentication Failed

**Cause**: Invalid or expired API key.

**Solution**:

```python
from ucid.api import UCIDClient

# Set API key
client = UCIDClient(
    api_key=os.environ["UCID_API_KEY"],
)

# Or use environment variable
export UCID_API_KEY=your_api_key
```

### Rate Limit Exceeded

**Cause**: Too many requests.

**Solution**:

```python
from ucid.api import UCIDClient

client = UCIDClient(
    rate_limit=True,        # Enable rate limiting
    requests_per_second=10, # Limit request rate
)
```

### Connection Timeout

**Cause**: Network issues or slow server.

**Solution**:

```python
client = UCIDClient(
    timeout=60,      # Increase timeout
    retries=3,       # Retry on failure
    backoff=True,    # Exponential backoff
)
```

---

## Docker Issues

### Container Won't Start

**Cause**: Port conflict or missing environment.

**Solution**:

```bash
# Check port availability
lsof -i :8000

# Use different port
docker run -p 8080:8000 ucid/ucid-api

# Check logs
docker logs ucid-container
```

### Database Connection Failed

**Cause**: Database not ready or wrong config.

**Solution**:

```bash
# Wait for database
docker-compose up -d database
sleep 10
docker-compose up -d api

# Check environment variables
docker exec ucid-container env | grep DATABASE
```

---

## Database Issues

### PostGIS Extension Missing

**Cause**: PostGIS not installed.

**Solution**:

```sql
CREATE EXTENSION IF NOT EXISTS postgis;
CREATE EXTENSION IF NOT EXISTS h3;
```

### Query Performance

**Cause**: Missing indexes.

**Solution**:

```sql
CREATE INDEX idx_ucid_h3 ON ucid_scores USING GIST (h3_cell);
CREATE INDEX idx_ucid_timestamp ON ucid_scores (timestamp);
```

---

## Debugging Techniques

### Enable Debug Logging

```python
import logging

logging.basicConfig(level=logging.DEBUG)
ucid_logger = logging.getLogger("ucid")
ucid_logger.setLevel(logging.DEBUG)
```

### Verbose Mode

```python
from ucid import create_ucid

ucid = create_ucid(
    city="IST",
    lat=41.015,
    lon=28.979,
    verbose=True,  # Print debug info
)
```

### Diagnostic Report

```python
from ucid.debug import diagnostic_report

report = diagnostic_report()
print(report)
```

---

## Getting Help

If you cannot resolve your issue:

1. Search [GitHub Issues](https://github.com/ucid-foundation/ucid/issues)
2. Ask in [GitHub Discussions](https://github.com/ucid-foundation/ucid/discussions)
3. Join our [Discord](https://discord.gg/ucid)
4. Email: support@ucid.org

---

Copyright 2026 UCID Foundation. All rights reserved.

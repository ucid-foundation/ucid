# Changelog

All notable changes to the UCID (Urban Context Identifier) project are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and follows the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

---

## Table of Contents

- [Unreleased](#unreleased)
- [1.0.0 - 2026-01-15](#100---2026-01-15)
- [0.9.0 - 2025-12-01](#090---2025-12-01)
- [0.8.0 - 2025-10-15](#080---2025-10-15)
- [0.7.0 - 2025-09-01](#070---2025-09-01)
- [0.6.0 - 2025-07-15](#060---2025-07-15)
- [0.5.0 - 2025-06-01](#050---2025-06-01)
- [0.4.0 - 2025-04-15](#040---2025-04-15)
- [0.3.0 - 2025-03-01](#030---2025-03-01)
- [0.2.0 - 2025-01-15](#020---2025-01-15)
- [0.1.0 - 2024-12-01](#010---2024-12-01)
- [Version Numbering](#version-numbering)
- [Deprecation Policy](#deprecation-policy)
- [Migration Guides](#migration-guides)

---

## Unreleased

### Added

- Experimental support for Python 3.14 (pending official release)
- New context: SAFETY (urban safety and security metrics)
- Real-time GTFS-RT integration for Helsinki (HSL) feeds
- S2 cell support as alternative to H3 indexing
- Async client for non-blocking API operations
- Support for Cloud Optimized GeoTIFF (COG) raster inputs
- New CLI command: `ucid export --format=pmtiles`
- Prometheus metrics endpoint for monitoring

### Changed

- Improved H3 polyfill performance for large bounding boxes (3x faster)
- Updated dependency versions for security patches
- Enhanced error messages with actionable suggestions
- Refactored context plugin loading for faster startup

### Deprecated

- The `h3_resolution` parameter will be renamed to `resolution` in v2.0.0
- Direct import from `ucid.core.parser` is deprecated; use `ucid` root module
- The `UCIDLegacy` class is deprecated and will be removed in v2.0.0

### Fixed

- Edge case in timestamp validation for week 53
- Memory leak in batch processing for very large datasets
- Incorrect coordinate sign handling in southern hemisphere
- Race condition in concurrent context scoring

---

## 1.0.0 - 2026-01-15

This is the first stable release of UCID, marking the library as production-ready for urban data analysis workflows.

### Added

#### Core Features
- UCID-V1 format specification with 11 colon-separated fields
- `create_ucid()` function for generating standardized identifiers
- `parse_ucid()` function with strict and permissive validation modes
- `canonicalize()` function for normalizing UCID representations
- Thread-safe city registry with default cities and custom registration
- Comprehensive validation with detailed error messages

#### Spatial Indexing
- H3 hexagonal indexing support (resolutions 0-15)
- H3 v3 and v4 API compatibility layer
- Grid generation over bounding boxes with `generate_grid_h3()`
- City-wide scanning with `scan_city_grid()` generator
- Coordinate conversion utilities (`latlng_to_cell`, `cell_to_latlng`)
- K-ring neighbor computation for spatial analysis
- Compact H3 indexing for efficient storage

#### Context Scoring System
- Pluggable `BaseContext` abstract class for custom contexts
- `ContextRegistry` for managing context implementations
- `ContextResult` dataclass for structured scoring results
- Six production-ready context implementations:
  - **15MIN**: 15-Minute City accessibility scoring
  - **TRANSIT**: Public transportation quality assessment
  - **CLIMATE**: Climate resilience and green space analysis
  - **VITALITY**: Urban vibrancy and activity measurement
  - **EQUITY**: Access equity across demographic groups
  - **WALK**: Walkability and pedestrian infrastructure

#### Data Integration
- OpenStreetMap integration via OSMnx
- GTFS static feed parsing and validation
- GTFS-RT real-time feed ingestion
- WorldPop and GHS-POP population data support
- Sentinel-2 satellite imagery processing (via rasterio)
- Data provenance tracking with `DataProvenance` class
- File-based caching for expensive data operations
- Configurable cache TTL and invalidation

#### Input/Output
- GeoParquet export with geometry encoding
- GeoJSON output for web applications
- CSV export with coordinate columns
- Shapefile output for legacy GIS compatibility
- GeoPackage support for desktop GIS
- Streaming export for large datasets

#### API and CLI
- FastAPI-based REST API with OpenAPI documentation
- Rate limiting and API key authentication
- Command-line interface for common operations
- Batch processing mode for production workflows
- JSON and table output formats

#### Developer Experience
- Full type annotations (PEP 484, PEP 561)
- Comprehensive test suite with 92% coverage
- Pre-commit hooks for code quality
- GitHub Actions CI/CD pipeline
- Docker images for containerized deployment

### Changed

- Minimum Python version is now 3.11 (was 3.10)
- H3 library version updated to 4.x
- Default H3 resolution changed from 8 to 9
- Context scoring now returns structured `ContextResult` objects

### Removed

- Python 3.9 support (end of life)
- Legacy `UCID.from_string()` method (use `parse_ucid()`)
- Deprecated `GridGenerator` class

### Security

- All dependencies audited for known vulnerabilities
- Input validation hardened against injection attacks
- API rate limiting enabled by default

---

## 0.9.0 - 2025-12-01

Release candidate for 1.0.0 with feature freeze.

### Added

- EQUITY context implementation
- WALK context implementation
- Batch UCID creation API
- Performance benchmarking suite
- Migration guide from 0.8.x

### Changed

- Stabilized public API for 1.0.0
- Improved documentation coverage
- Enhanced error handling

### Fixed

- Context scoring edge cases
- Memory optimization for large grids
- Thread safety in registry operations

---

## 0.8.0 - 2025-10-15

### Added

- CLIMATE context with NDVI and LST support
- VITALITY context for urban activity measurement
- Sentinel-2 satellite data integration
- WorldPop population data support
- File-based caching system
- Data provenance tracking

### Changed

- Refactored context architecture for plugin support
- Improved H3 grid generation performance
- Updated OSM tag mappings

### Fixed

- GTFS feed timezone handling
- Coordinate precision in parsing
- Cache invalidation logic

---

## 0.7.0 - 2025-09-01

### Added

- TRANSIT context with GTFS support
- 15MIN context for walkable city analysis
- GeoParquet export format
- Docker containerization
- GitHub Actions CI/CD

### Changed

- Unified scoring scale (0-100)
- Standardized grade assignment
- Improved API documentation

### Fixed

- H3 edge cases at antimeridian
- City code validation
- Timestamp parsing for edge weeks

---

## 0.6.0 - 2025-07-15

### Added

- Context scoring framework
- BaseContext abstract class
- ContextRegistry for plugins
- Initial 15MIN prototype
- CLI scoring command

### Changed

- Modularized codebase structure
- Enhanced type annotations
- Improved test coverage

---

## 0.5.0 - 2025-06-01

### Added

- H3 grid generation utilities
- City registry system
- Bounding box operations
- K-ring neighbor computation
- Spatial aggregation functions

### Changed

- Migrated to H3 v4 API
- Updated coordinate encoding
- Improved validation messages

---

## 0.4.0 - 2025-04-15

### Added

- UCID parsing with validation
- Canonicalization function
- Coordinate extraction
- Timestamp parsing
- Error hierarchy

### Changed

- Refined format specification
- Enhanced documentation
- Added more test cases

---

## 0.3.0 - 2025-03-01

### Added

- Basic UCID creation
- Format version support
- City code validation
- H3 index generation
- Initial documentation

### Changed

- Field ordering in UCID string
- Coordinate precision handling

---

## 0.2.0 - 2025-01-15

### Added

- Project structure
- Core module skeleton
- Type definitions
- Basic tests
- CI configuration

---

## 0.1.0 - 2024-12-01

Initial development release.

### Added

- Repository initialization
- License (EUPL-1.2)
- Basic README
- Development setup

---

## Version Numbering

UCID follows Semantic Versioning 2.0.0:

| Version | Meaning |
|---------|---------|
| MAJOR (X.0.0) | Breaking API changes |
| MINOR (0.X.0) | New backward-compatible features |
| PATCH (0.0.X) | Backward-compatible bug fixes |

### Pre-release Versions

| Stage | Format | Stability |
|-------|--------|-----------|
| Alpha | X.Y.Z-alpha.N | Unstable, incomplete |
| Beta | X.Y.Z-beta.N | Feature complete, testing |
| RC | X.Y.Z-rc.N | Release candidate |

---

## Deprecation Policy

### Deprecation Timeline

| Version | Action |
|---------|--------|
| N | Feature deprecated, warning emitted |
| N+1 | Warning promoted to DeprecationWarning |
| N+2 | Feature removed |

### Deprecation Notice Format

```python
import warnings
warnings.warn(
    "Function X is deprecated and will be removed in version Y. "
    "Use function Z instead.",
    DeprecationWarning,
    stacklevel=2,
)
```

---

## Migration Guides

### Migrating from 0.x to 1.0

#### Breaking Changes

1. **Minimum Python Version**: Upgrade to Python 3.11+
2. **Import Changes**: Use `from ucid import create_ucid` instead of `from ucid.core.parser import create_ucid`
3. **H3 Resolution**: Default changed from 8 to 9; specify explicitly if needed
4. **Context Results**: Now returns `ContextResult` object instead of dict

#### Migration Steps

```python
# Old (0.x)
from ucid.core.parser import create_ucid
ucid = create_ucid(city="IST", lat=41.015, lon=28.979, h3_resolution=8)

# New (1.0)
from ucid import create_ucid
ucid = create_ucid(city="IST", lat=41.015, lon=28.979, resolution=9)
```

### Migrating from 0.8 to 0.9

- No breaking changes
- Update dependency versions
- Review deprecation warnings

---

## Links

- [GitHub Releases](https://github.com/ucid-foundation/ucid/releases)
- [PyPI Package](https://pypi.org/project/ucid/)
- [Documentation](https://ucid.readthedocs.io/)
- [Migration Guides](https://ucid.readthedocs.io/en/latest/migration/)

---

Copyright 2026 UCID Foundation. All rights reserved.

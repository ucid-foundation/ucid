# UCID Changelog

## Document Information

| Field | Value |
|-------|-------|
| Document Title | UCID Release History and Changelog |
| Version | 1.0.5 |
| Last Updated | 2026-01-16 |
| Maintainer | UCID Foundation |
| Format | [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) |
| Versioning | [Semantic Versioning](https://semver.org/spec/v2.0.0.html) |

---

## Table of Contents

1. [Unreleased](#unreleased)
2. [Version 1.0.5](#105---2026-01-15)
3. [Version 1.0.4](#104---2026-01-10)
4. [Version 1.0.3](#103---2026-01-05)
5. [Version 1.0.2](#102---2025-12-20)
6. [Version 1.0.1](#101---2025-12-15)
7. [Version 1.0.0](#100---2025-12-01)
8. [Version 0.9.0](#090---2025-11-15)
9. [Version 0.8.0](#080---2025-10-15)
10. [Version 0.7.0](#070---2025-09-01)
11. [Version 0.6.0](#060---2025-07-15)
12. [Version 0.5.0](#050---2025-06-01)
13. [Version 0.4.0](#040---2025-04-15)
14. [Version 0.3.0](#030---2025-03-01)
15. [Version 0.2.0](#020---2025-01-15)
16. [Version 0.1.0](#010---2024-12-01)
17. [Version Numbering](#version-numbering)
18. [Deprecation Policy](#deprecation-policy)
19. [Migration Guides](#migration-guides)

---

## Library Statistics

| Metric | Value |
|--------|-------|
| Total Cities | 405 |
| Countries | 23 |
| CREATE Performance | 127,575 ops/sec |
| PARSE Performance | 61,443 ops/sec |
| VALIDATE Performance | 17,334 ops/sec |

---

## Unreleased

### Added

- Experimental support for Python 3.14 (pending official release)
- New context algorithm: SAFETY (urban safety metrics) - planned
- Real-time GTFS-RT integration for additional cities
- S2 cell support as alternative spatial indexing option
- Async client for non-blocking API operations
- Cloud Optimized GeoTIFF (COG) raster input support
- New CLI command: `ucid export --format=pmtiles`
- Prometheus metrics endpoint for production monitoring
- OpenTelemetry tracing integration

### Changed

- Improved H3 polyfill performance for large bounding boxes (target: 3x faster)
- Enhanced error messages with actionable suggestions
- Refactored context plugin loading for faster startup time
- Updated dependency versions for security patches

### Deprecated

- Parameter `h3_resolution` will be renamed to `resolution` in v2.0.0
- Function `get_city_by_code()` deprecated in favor of `get_city()`

### Security

- Updated cryptography dependency to address CVE-2026-XXXXX
- Enhanced API key validation with constant-time comparison

---

## [1.0.5] - 2026-01-15

### Summary

Production release with expanded city coverage and performance optimizations.

### Statistics

| Metric | Value |
|--------|-------|
| Cities Added | 15 |
| Total Cities | 405 |
| Countries | 23 |
| Performance Improvement | 8% |

### Added

- 15 new cities across Europe and Asia
- Academic dataset with 1,000,000 UCID records
- Zenodo DOI: 10.5281/zenodo.18256962
- Enhanced documentation with Mermaid diagrams
- LaTeX formulas in technical documentation
- Comprehensive Google OSS compliance

### Changed

- Updated city registry metadata format
- Improved validation error messages
- Enhanced type hints coverage to 100%
- Refactored context scoring algorithms

### Fixed

- City code validation for edge cases
- H3 index generation for polar coordinates
- Timestamp parsing for week 53 edge cases
- Memory leak in batch processing operations

### Performance

| Operation | Before | After | Improvement |
|-----------|--------|-------|-------------|
| CREATE | 118,000 ops/sec | 127,575 ops/sec | +8.1% |
| PARSE | 58,000 ops/sec | 61,443 ops/sec | +5.9% |
| VALIDATE | 16,500 ops/sec | 17,334 ops/sec | +5.1% |

---

## [1.0.4] - 2026-01-10

### Summary

Bug fix release with improved stability.

### Fixed

- Race condition in concurrent UCID creation
- Memory leak in long-running API processes
- Incorrect grade calculation for boundary scores
- CLI crash when processing empty input files

### Changed

- Improved error handling in GTFS parser
- Enhanced logging for debugging

---

## [1.0.3] - 2026-01-05

### Summary

Security patch and dependency updates.

### Security

- Updated h3 library to 4.1.0 (security fix)
- Patched potential XSS in API error responses
- Enhanced input sanitization

### Changed

- Updated all dependencies to latest stable versions
- Improved Docker image security (non-root user)

---

## [1.0.2] - 2025-12-20

### Summary

Performance optimization release.

### Added

- Batch processing API endpoint
- Connection pooling for database operations
- LRU cache for city registry lookups

### Performance

| Operation | Improvement |
|-----------|-------------|
| Batch CREATE | 3x faster |
| City lookup | 10x faster (cached) |

### Fixed

- Timeout issues with large grid operations
- Memory usage in multi-context scoring

---

## [1.0.1] - 2025-12-15

### Summary

Bug fix release following initial stable release.

### Fixed

- Installation issues on Windows
- Missing py.typed marker in package
- Incorrect H3 resolution validation
- Documentation typos

### Changed

- Improved error messages for invalid coordinates
- Enhanced CLI help text

---

## [1.0.0] - 2025-12-01

### Summary

First stable production release of UCID.

### Highlights

- 390 cities across 21 countries
- 4 production contexts: 15MIN, TRANSIT, WALK, NONE
- Full Python 3.11+ support
- Comprehensive documentation
- 85%+ test coverage

### Added

- Complete UCID specification v1.0
- Core parser with create/parse/validate functions
- City registry with 390 cities
- Context algorithms: 15MIN, TRANSIT, WALK, NONE
- H3 spatial indexing integration
- ISO week timestamp support
- Grade scale A-F with thresholds
- Confidence scoring system
- CLI with create, parse, validate commands
- REST API with FastAPI
- GeoJSON export functionality
- Comprehensive test suite
- Full documentation

### API

```python
from ucid import create_ucid, parse_ucid

# Create UCID
ucid = create_ucid(
    city="IST",
    lat=41.015,
    lon=28.979,
    timestamp="2025W48T14",
    context="15MIN",
)

# Parse UCID
parsed = parse_ucid(str(ucid))
print(f"City: {parsed.city}, Grade: {parsed.grade}")
```

---

## [0.9.0] - 2025-11-15

### Summary

Release candidate with feature freeze.

### Added

- Final API stabilization
- Performance benchmarking suite
- Production deployment documentation
- Security hardening

### Changed

- Frozen public API for 1.0
- Final documentation review

### Removed

- Deprecated experimental features
- Legacy compatibility code

---

## [0.8.0] - 2025-10-15

### Summary

Beta release with expanded city coverage.

### Added

- 150 new cities (total: 350)
- WALK context algorithm
- Batch processing support
- Parquet export format

### Changed

- Improved 15MIN algorithm accuracy
- Enhanced TRANSIT scoring model

---

## [0.7.0] - 2025-09-01

### Summary

Beta release with TRANSIT context.

### Added

- TRANSIT context algorithm
- GTFS feed integration
- Service frequency scoring
- Temporal adjustments for rush hour

### Changed

- Refactored context base class
- Improved plugin architecture

---

## [0.6.0] - 2025-07-15

### Summary

Alpha release with 15MIN context.

### Added

- 15MIN context algorithm
- OSM data integration
- Amenity category scoring
- Walking distance calculations

### Changed

- Enhanced scoring formula
- Improved weight configuration

---

## [0.5.0] - 2025-06-01

### Summary

Alpha release with REST API.

### Added

- FastAPI-based REST API
- Authentication with API keys
- Rate limiting
- OpenAPI documentation

---

## [0.4.0] - 2025-04-15

### Summary

Alpha release with CLI.

### Added

- Command-line interface
- Create, parse, validate commands
- JSON output format
- Verbose mode

---

## [0.3.0] - 2025-03-01

### Summary

Alpha release with validation.

### Added

- Comprehensive validation rules
- H3 index verification
- City registry validation
- Coordinate bounds checking

---

## [0.2.0] - 2025-01-15

### Summary

Alpha release with city registry.

### Added

- Initial city registry (50 cities)
- City lookup functions
- Country grouping
- Coordinate search

---

## [0.1.0] - 2024-12-01

### Summary

Initial alpha release.

### Added

- UCID format specification
- Basic parser implementation
- Core data models
- Project structure

---

## Version Numbering

UCID follows Semantic Versioning 2.0.0:

```
MAJOR.MINOR.PATCH
```

| Component | When to Increment |
|-----------|-------------------|
| MAJOR | Breaking API changes |
| MINOR | New features (backward compatible) |
| PATCH | Bug fixes (backward compatible) |

### Pre-release Versions

| Format | Meaning |
|--------|---------|
| X.Y.Z-alpha.N | Early development |
| X.Y.Z-beta.N | Feature complete, testing |
| X.Y.Z-rc.N | Release candidate |

---

## Deprecation Policy

### Timeline

| Phase | Duration | Action |
|-------|----------|--------|
| Announcement | Release N | Deprecation warning added |
| Warning Period | Release N to N+2 | Warning on usage |
| Removal | Release N+3 | Feature removed |

### Handling Deprecations

```python
import warnings

# Check for deprecation warnings
warnings.filterwarnings("error", category=DeprecationWarning)
```

---

## Migration Guides

### Migrating from 0.x to 1.0

1. Update import statements
2. Replace deprecated functions
3. Update configuration format
4. Run test suite

### Breaking Changes in 1.0

| Change | Migration |
|--------|-----------|
| `UCIDParser` class removed | Use `parse_ucid()` function |
| `grade` now uppercase | Update string comparisons |
| `confidence` now float | Update type annotations |

---

## Release Schedule

| Version | Target Date | Status |
|---------|-------------|--------|
| 1.0.5 | 2026-01-15 | Released |
| 1.1.0 | 2026-03-01 | Planned |
| 1.2.0 | 2026-06-01 | Planned |
| 2.0.0 | 2026-12-01 | Planned |

---

## Contributors

See [CONTRIBUTORS.md](CONTRIBUTORS.md) for the full list of contributors to each release.

---

## References

- [Keep a Changelog](https://keepachangelog.com/)
- [Semantic Versioning](https://semver.org/)
- [Python versioning](https://peps.python.org/pep-0440/)

---

Copyright 2026 UCID Foundation. All rights reserved.
Licensed under EUPL-1.2.

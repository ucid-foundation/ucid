# Testing Guide

This document provides comprehensive guidance on testing the UCID (Urban Context Identifier) project, including test strategies, running tests, and writing new tests.

---

## Table of Contents

1. [Overview](#overview)
2. [Test Categories](#test-categories)
3. [Running Tests](#running-tests)
4. [Test Configuration](#test-configuration)
5. [Writing Tests](#writing-tests)
6. [Mocking and Fixtures](#mocking-and-fixtures)
7. [Coverage](#coverage)
8. [Performance Testing](#performance-testing)
9. [Integration Testing](#integration-testing)
10. [CI/CD Testing](#cicd-testing)

---

## Overview

### Testing Philosophy

UCID follows a comprehensive testing strategy:

| Principle | Description |
|-----------|-------------|
| **Test Pyramid** | Many unit tests, fewer integration tests, few E2E tests |
| **TDD Optional** | Tests encouraged but TDD not required |
| **Coverage Goals** | 90% line coverage target |
| **Fast Tests** | Unit tests should be fast |

### Test Stack

| Tool | Purpose |
|------|---------|
| pytest | Test framework |
| pytest-cov | Coverage reporting |
| pytest-xdist | Parallel execution |
| pytest-mock | Mocking |
| hypothesis | Property-based testing |
| pytest-asyncio | Async test support |
| pytest-benchmark | Performance tests |

---

## Test Categories

### Unit Tests

Fast, isolated tests for individual functions and classes.

```python
# tests/unit/test_parser.py
import pytest
from ucid import create_ucid, parse_ucid

def test_create_ucid_valid():
    """Test UCID creation with valid inputs."""
    ucid = create_ucid(
        city="IST",
        lat=41.015,
        lon=28.979,
        timestamp="2026W01T12",
        context="15MIN",
    )
    assert ucid.startswith("UCID:V1:IST:")

def test_create_ucid_invalid_city():
    """Test UCID creation with invalid city."""
    with pytest.raises(UCIDValidationError):
        create_ucid(city="XXX", lat=0, lon=0)
```

### Integration Tests

Tests that verify component interactions.

```python
# tests/integration/test_context_data.py
import pytest
from ucid.contexts import get_context
from ucid.data import OSMFetcher

@pytest.mark.integration
def test_context_with_osm_data():
    """Test context scoring with real OSM data."""
    context = get_context("15MIN")
    result = context.compute(
        lat=41.015,
        lon=28.979,
        timestamp="2026W01T12",
    )
    assert 0 <= result.score <= 100
```

### End-to-End Tests

Tests that verify complete workflows.

```python
# tests/e2e/test_api_workflow.py
import pytest
from httpx import AsyncClient

@pytest.mark.e2e
@pytest.mark.asyncio
async def test_create_and_retrieve_ucid():
    """Test complete API workflow."""
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Create UCID
        response = await client.post("/v1/ucid/create", json={
            "city": "IST",
            "lat": 41.015,
            "lon": 28.979,
        })
        assert response.status_code == 201
        ucid_id = response.json()["id"]

        # Retrieve UCID
        response = await client.get(f"/v1/ucid/{ucid_id}")
        assert response.status_code == 200
```

---

## Running Tests

### Basic Commands

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/unit/test_parser.py

# Run specific test function
pytest tests/unit/test_parser.py::test_create_ucid_valid

# Run tests matching pattern
pytest -k "ucid and valid"
```

### Test Categories

```bash
# Run only unit tests
pytest tests/unit/

# Run only integration tests
pytest -m integration

# Run only E2E tests
pytest -m e2e

# Exclude slow tests
pytest -m "not slow"
```

### Parallel Execution

```bash
# Run tests in parallel
pytest -n auto

# Use specific number of workers
pytest -n 4
```

### Watch Mode

```bash
# Rerun on file changes
pytest-watch
# or
ptw
```

---

## Test Configuration

### pytest.ini

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --strict-markers
markers =
    unit: Unit tests
    integration: Integration tests
    e2e: End-to-end tests
    slow: Slow tests
    network: Tests requiring network
```

### conftest.py

```python
# tests/conftest.py
import pytest
from ucid import register_city

@pytest.fixture(scope="session")
def test_city():
    """Register test city for all tests."""
    register_city(
        code="TST",
        name="Test City",
        country="XX",
        lat=0.0,
        lon=0.0,
    )
    return "TST"

@pytest.fixture
def sample_ucid():
    """Return sample UCID for testing."""
    return "UCID:V1:IST:8a3b5c2d1e0f:2026W01T12:15MIN:72:B:95"

@pytest.fixture
def mock_osm_response():
    """Mock OSM API response."""
    return {
        "elements": [
            {"type": "node", "id": 1, "lat": 41.015, "lon": 28.979},
        ]
    }
```

---

## Writing Tests

### Test Structure

Follow the AAA pattern:

```python
def test_example():
    # Arrange - Set up test data
    city = "IST"
    lat = 41.015
    lon = 28.979

    # Act - Execute the function
    ucid = create_ucid(city=city, lat=lat, lon=lon)

    # Assert - Verify the result
    assert ucid.startswith("UCID:V1:IST:")
```

### Testing Classes

```python
class TestUCIDParser:
    """Tests for UCID parser."""

    def test_parse_valid_ucid(self):
        """Test parsing valid UCID string."""
        ucid = parse_ucid("UCID:V1:IST:8a3b:2026W01T12:15MIN:72:B:95")
        assert ucid.city == "IST"
        assert ucid.score == 72

    def test_parse_invalid_format(self):
        """Test parsing invalid UCID string."""
        with pytest.raises(UCIDParseError):
            parse_ucid("invalid")

    @pytest.mark.parametrize("city", ["IST", "NYC", "LON"])
    def test_parse_various_cities(self, city):
        """Test parsing UCIDs with various cities."""
        ucid_str = f"UCID:V1:{city}:8a3b:2026W01T12:15MIN:72:B:95"
        ucid = parse_ucid(ucid_str)
        assert ucid.city == city
```

### Parametrized Tests

```python
@pytest.mark.parametrize("lat,lon,expected", [
    (0, 0, True),
    (90, 180, True),
    (-90, -180, True),
    (91, 0, False),
    (0, 181, False),
])
def test_coordinate_validation(lat, lon, expected):
    """Test coordinate validation with various inputs."""
    result = validate_coordinates(lat, lon)
    assert result == expected
```

---

## Mocking and Fixtures

### Using pytest-mock

```python
def test_with_mock(mocker):
    """Test with mocked dependency."""
    mock_fetch = mocker.patch("ucid.data.osm.fetch_pois")
    mock_fetch.return_value = [{"name": "Test POI"}]

    result = compute_accessibility(lat=41.0, lon=28.9)

    mock_fetch.assert_called_once()
    assert result > 0
```

### Custom Fixtures

```python
@pytest.fixture
def mock_gtfs_feed(tmp_path):
    """Create mock GTFS feed for testing."""
    gtfs_dir = tmp_path / "gtfs"
    gtfs_dir.mkdir()

    # Create minimal GTFS files
    (gtfs_dir / "agency.txt").write_text(
        "agency_id,agency_name\n1,Test Agency"
    )
    (gtfs_dir / "routes.txt").write_text(
        "route_id,agency_id,route_type\n1,1,3"
    )

    return gtfs_dir
```

---

## Coverage

### Running Coverage

```bash
# Run with coverage
pytest --cov=ucid

# Generate HTML report
pytest --cov=ucid --cov-report=html

# Show missing lines
pytest --cov=ucid --cov-report=term-missing
```

### Coverage Configuration

```ini
# .coveragerc
[run]
source = src/ucid
branch = True
omit =
    */tests/*
    */__pycache__/*

[report]
fail_under = 90
show_missing = True
exclude_lines =
    pragma: no cover
    raise NotImplementedError
    if TYPE_CHECKING:
```

---

## Performance Testing

### Using pytest-benchmark

```python
def test_create_ucid_performance(benchmark):
    """Benchmark UCID creation."""
    result = benchmark(
        create_ucid,
        city="IST",
        lat=41.015,
        lon=28.979,
    )
    assert result is not None
```

### Running Benchmarks

```bash
# Run benchmarks
pytest tests/benchmarks/ --benchmark-only

# Compare with previous run
pytest --benchmark-compare

# Save results
pytest --benchmark-save=baseline
```

---

## Integration Testing

### Database Tests

```python
@pytest.fixture
def db_session():
    """Create test database session."""
    engine = create_engine("postgresql://test@localhost/ucid_test")
    with Session(engine) as session:
        yield session
        session.rollback()

def test_save_ucid(db_session):
    """Test saving UCID to database."""
    ucid = create_ucid(city="IST", lat=41.0, lon=28.9)
    db_session.add(UCIDRecord(ucid_string=str(ucid)))
    db_session.commit()

    result = db_session.query(UCIDRecord).first()
    assert result is not None
```

### API Tests

```python
from fastapi.testclient import TestClient
from ucid.api import app

client = TestClient(app)

def test_api_health():
    """Test API health endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
```

---

## CI/CD Testing

### GitHub Actions

```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install -e ".[dev]"
      - run: pytest --cov=ucid --cov-report=xml
      - uses: codecov/codecov-action@v4
```

### Test Matrix

| Python | OS | Status |
|--------|-----|--------|
| 3.11 | Ubuntu | Required |
| 3.12 | Ubuntu | Required |
| 3.13 | Ubuntu | Optional |
| 3.12 | macOS | Required |
| 3.12 | Windows | Required |

---

## Best Practices

### Do's

| Practice | Reason |
|----------|--------|
| Use descriptive names | Clear test purpose |
| Test one thing per test | Easy debugging |
| Use fixtures | Reduce duplication |
| Test edge cases | Catch bugs early |

### Don'ts

| Practice | Why Avoid |
|----------|-----------|
| Test implementation | Fragile tests |
| Depend on test order | Flaky tests |
| Use production data | Privacy, size |
| Skip error cases | Missing coverage |

---

## Getting Help

- [pytest Documentation](https://docs.pytest.org/)
- [Testing Best Practices](https://ucid.readthedocs.io/testing/)
- GitHub Discussions

---

Copyright 2026 UCID Foundation. All rights reserved.

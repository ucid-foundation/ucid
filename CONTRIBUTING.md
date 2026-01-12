# Contributing to UCID

This document provides comprehensive guidelines for contributing to the UCID (Urban Context Identifier) project. We welcome contributions from researchers, developers, urban planners, and data scientists who share our vision of standardized urban data analysis.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Environment](#development-environment)
4. [Code Standards](#code-standards)
5. [Testing Requirements](#testing-requirements)
6. [Documentation Standards](#documentation-standards)
7. [Commit Message Convention](#commit-message-convention)
8. [Pull Request Process](#pull-request-process)
9. [Review Process](#review-process)
10. [Release Process](#release-process)
11. [Issue Guidelines](#issue-guidelines)
12. [Security Vulnerabilities](#security-vulnerabilities)
13. [Governance](#governance)
14. [Recognition](#recognition)

---

## Code of Conduct

All contributors must adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project, you agree to maintain a respectful, inclusive, and harassment-free environment. Violations of the Code of Conduct may result in temporary or permanent exclusion from the project.

### Core Principles

1. **Respect**: Treat all community members with dignity and respect
2. **Inclusivity**: Welcome contributors regardless of background, identity, or experience level
3. **Collaboration**: Work together constructively toward shared goals
4. **Transparency**: Communicate openly and honestly
5. **Accountability**: Take responsibility for your actions and their impact

---

## Getting Started

### Prerequisites

Before contributing to UCID, ensure you have the following:

| Requirement | Minimum Version | Recommended Version |
|-------------|-----------------|---------------------|
| Python | 3.11 | 3.12 |
| Git | 2.30 | Latest |
| pip | 23.0 | Latest |
| Operating System | Linux, macOS, Windows | Linux (Ubuntu 22.04) |

### Repository Structure

Understanding the repository structure is essential for effective contribution:

```
ucid/
├── src/ucid/              # Main package source code
│   ├── api/               # REST API implementation
│   ├── client/            # HTTP client library
│   ├── compute/           # Distributed computing backends
│   ├── contexts/          # Context scoring algorithms
│   ├── core/              # Core parsing and models
│   ├── data/              # Data source connectors
│   ├── i18n/              # Internationalization
│   ├── io/                # Input/output operations
│   ├── ml/                # Machine learning module
│   ├── monitoring/        # Observability utilities
│   ├── realtime/          # Real-time data ingestion
│   ├── scoring/           # Score calibration and uncertainty
│   ├── spatial/           # Spatial indexing operations
│   ├── temporal/          # Time series analysis
│   ├── utils/             # Common utilities
│   └── viz/               # Visualization utilities
├── tests/                 # Test suite
│   ├── unit/              # Unit tests
│   ├── integration/       # Integration tests
│   └── performance/       # Performance benchmarks
├── docs/                  # Documentation
│   └── instructions/      # Detailed instruction documents
├── notebooks/             # Jupyter notebooks
├── scripts/               # Utility scripts
└── examples/              # Example applications
```

### Forking and Cloning

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/YOUR_USERNAME/ucid.git
cd ucid
```

3. Add the upstream remote:

```bash
git remote add upstream https://github.com/ucid-foundation/ucid.git
```

4. Create a development branch:

```bash
git checkout -b feature/your-feature-name
```

---

## Development Environment

### Setting Up the Environment

Create a virtual environment and install development dependencies:

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Linux/macOS:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev,contexts,viz]"

# Install pre-commit hooks
pre-commit install
```

### IDE Configuration

We recommend using Visual Studio Code or PyCharm with the following settings:

**Visual Studio Code settings.json:**

```json
{
    "python.linting.enabled": true,
    "python.linting.ruffEnabled": true,
    "python.formatting.provider": "none",
    "[python]": {
        "editor.formatOnSave": true,
        "editor.codeActionsOnSave": {
            "source.fixAll.ruff": true,
            "source.organizeImports.ruff": true
        }
    },
    "python.analysis.typeCheckingMode": "strict"
}
```

### Environment Variables

The following environment variables can be configured for development:

| Variable | Description | Default |
|----------|-------------|---------|
| `UCID_LOG_LEVEL` | Logging verbosity | `INFO` |
| `UCID_CACHE_DIR` | Cache directory path | `.ucid_cache` |
| `UCID_API_KEY` | API key for remote services | None |
| `UCID_DEBUG` | Enable debug mode | `false` |

---

## Code Standards

### Python Style Guide

UCID follows the Google Python Style Guide with the following specifications:

1. **Line Length**: Maximum 88 characters (Black/Ruff default)
2. **Indentation**: 4 spaces (no tabs)
3. **Quotes**: Double quotes for strings
4. **Imports**: Grouped and sorted by Ruff

### Type Annotations

All public functions and methods must include type annotations. Use modern Python 3.11+ syntax:

```python
# Correct: Modern type hints
def process_coordinates(
    lat: float,
    lon: float,
    options: dict[str, Any] | None = None,
) -> list[str]:
    ...

# Incorrect: Legacy typing module
def process_coordinates(
    lat: float,
    lon: float,
    options: Optional[Dict[str, Any]] = None,
) -> List[str]:
    ...
```

### Docstring Format

All public modules, classes, and functions must have Google-style docstrings:

```python
def create_ucid(
    city: str,
    lat: float,
    lon: float,
    timestamp: str,
    context: str,
    grade: str = "F",
    confidence: float = 0.0,
) -> UCID:
    """Create a new UCID object from coordinates and metadata.

    This function creates a UCID with automatic H3 index computation if
    not provided. The resulting UCID is validated before being returned.

    Args:
        city: 3-character city code (must be in registry).
        lat: Latitude in decimal degrees (-90 to 90).
        lon: Longitude in decimal degrees (-180 to 180).
        timestamp: Temporal key in ISO week format (YYYYWwwThh).
        context: Context identifier (e.g., "15MIN", "TRANSIT").
        grade: Quality grade. Defaults to "F".
        confidence: Confidence score (0.0 to 1.0). Defaults to 0.0.

    Returns:
        Validated UCID object.

    Raises:
        UCIDValidationError: If any parameter fails validation.

    Example:
        >>> ucid = create_ucid(
        ...     city="IST",
        ...     lat=41.015,
        ...     lon=28.979,
        ...     timestamp="2026W01T12",
        ...     context="15MIN",
        ... )
    """
```

### Error Handling

Use custom exception classes defined in `ucid.core.errors`:

```python
from ucid.core.errors import UCIDParseError, UCIDValidationError

def validate_city_code(code: str) -> None:
    if len(code) != 3:
        raise UCIDValidationError(
            f"City code must be 3 characters, got {len(code)}",
            code="INVALID_CITY_CODE",
            details={"provided": code},
        )
```

### Linting and Formatting

Run the following commands before committing:

```bash
# Format code
ruff format src/ tests/

# Lint and fix
ruff check --fix src/ tests/

# Type check
mypy src/ucid

# Run all checks
pre-commit run --all-files
```

---

## Testing Requirements

### Test Coverage

All new code must include tests with the following coverage requirements:

| Component | Minimum Coverage |
|-----------|------------------|
| Core modules | 90% |
| Context algorithms | 85% |
| API endpoints | 80% |
| Utilities | 75% |

### Test Structure

Tests are organized into three categories:

1. **Unit Tests** (`tests/unit/`): Test individual functions and classes in isolation
2. **Integration Tests** (`tests/integration/`): Test component interactions
3. **Performance Tests** (`tests/performance/`): Benchmark critical operations

### Writing Tests

Use pytest with the following conventions:

```python
import pytest
from ucid import create_ucid, parse_ucid
from ucid.core.errors import UCIDParseError


class TestParseUCID:
    """Tests for the parse_ucid function."""

    def test_parse_valid_ucid(self) -> None:
        """Test parsing a valid UCID string."""
        ucid_string = "UCID-V1:IST:+41.015:+28.979:9:891f2ed6df7ffff:2026W01T12:15MIN:A:0.95:"
        result = parse_ucid(ucid_string)
        
        assert result.city == "IST"
        assert result.lat == pytest.approx(41.015, rel=1e-3)
        assert result.context == "15MIN"

    def test_parse_invalid_prefix_raises_error(self) -> None:
        """Test that invalid prefix raises UCIDParseError."""
        with pytest.raises(UCIDParseError) as exc_info:
            parse_ucid("INVALID:IST:+41.015:+28.979:...")
        
        assert exc_info.value.code == "INVALID_PREFIX"

    @pytest.mark.parametrize("city", ["IST", "NYC", "LON", "HEL"])
    def test_parse_various_cities(self, city: str) -> None:
        """Test parsing UCIDs for various cities."""
        ucid = create_ucid(
            city=city,
            lat=40.0,
            lon=28.0,
            timestamp="2026W01T12",
            context="15MIN",
        )
        parsed = parse_ucid(str(ucid))
        assert parsed.city == city
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/unit/test_core_parser.py -v

# Run with coverage
pytest tests/ --cov=ucid --cov-report=html

# Run only unit tests
pytest tests/unit/ -v

# Run integration tests
pytest tests/integration/ -v -m integration

# Run performance benchmarks
pytest tests/performance/ --benchmark-only
```

---

## Documentation Standards

### Module Documentation

Every module must have a module-level docstring explaining its purpose:

```python
"""UCID Spatial Operations Module.

This module provides spatial indexing operations for the UCID library,
including H3 hexagonal indexing, S2 cell operations, and grid generation
utilities.

The module supports both H3 v3 and v4 APIs through a compatibility layer,
ensuring consistent behavior across versions.

Example:
    >>> from ucid.spatial import latlng_to_cell, cell_to_latlng
    >>> h3_index = latlng_to_cell(41.015, 28.979, resolution=9)
    >>> lat, lon = cell_to_latlng(h3_index)
"""
```

### API Documentation

API documentation is generated automatically using Sphinx. Ensure all public APIs have complete docstrings.

### Instruction Documents

When adding significant features, create or update the relevant instruction document in `docs/instructions/`.

---

## Commit Message Convention

UCID follows the Conventional Commits specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `style` | Formatting changes |
| `refactor` | Code refactoring |
| `perf` | Performance improvements |
| `test` | Test additions or modifications |
| `build` | Build system changes |
| `ci` | CI configuration changes |
| `chore` | Maintenance tasks |

### Examples

```
feat(contexts): add walkability context scoring algorithm

Implement the WALK context for pedestrian infrastructure analysis.
Includes sidewalk coverage, intersection density, and traffic safety
scoring components.

Closes #123
```

```
fix(parser): handle edge case in timestamp validation

The timestamp validation was incorrectly rejecting week 53 in years
that have 53 ISO weeks. Updated regex pattern and added comprehensive
test coverage.

Fixes #456
```

---

## Pull Request Process

### Before Submitting

1. Ensure all tests pass locally
2. Run linting and formatting checks
3. Update documentation if needed
4. Add entries to CHANGELOG.md if applicable

### PR Template

When creating a pull request, fill out the provided template completely:

1. **Description**: Clear explanation of changes
2. **Related Issue**: Link to related issue
3. **Type of Change**: Bug fix, feature, breaking change, etc.
4. **Checklist**: Confirm all requirements are met

### PR Size Guidelines

| Size | Lines Changed | Review Time |
|------|---------------|-------------|
| Small | < 100 | 1-2 days |
| Medium | 100-500 | 2-3 days |
| Large | 500-1000 | 3-5 days |
| Extra Large | > 1000 | Split recommended |

---

## Review Process

### Review Criteria

All pull requests are reviewed for:

1. **Correctness**: Does the code work as intended?
2. **Test Coverage**: Are there sufficient tests?
3. **Code Quality**: Does it follow our standards?
4. **Documentation**: Is it properly documented?
5. **Performance**: Are there any performance concerns?
6. **Security**: Are there any security implications?

### Approval Requirements

| Change Type | Required Approvals |
|-------------|-------------------|
| Documentation | 1 maintainer |
| Bug fixes | 1 maintainer |
| New features | 2 maintainers |
| Breaking changes | 2 maintainers + core team review |

---

## Release Process

Releases follow semantic versioning (SemVer 2.0.0):

- **Major** (X.0.0): Breaking API changes
- **Minor** (0.X.0): New features, backward compatible
- **Patch** (0.0.X): Bug fixes, backward compatible

See [Release Process](docs/instructions/28_release_process.md) for detailed procedures.

---

## Issue Guidelines

### Bug Reports

When reporting bugs, include:

1. UCID version (`ucid --version`)
2. Python version
3. Operating system
4. Minimal reproducible example
5. Expected vs actual behavior
6. Full error message and stack trace

### Feature Requests

When requesting features:

1. Describe the problem being solved
2. Propose a solution
3. List alternatives considered
4. Provide use case examples

---

## Security Vulnerabilities

Do not report security vulnerabilities through public GitHub issues.

Instead, email security@ucid.org with:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

See [SECURITY.md](SECURITY.md) for our full security policy.

---

## Governance

UCID is governed by the UCID Foundation. See [GOVERNANCE.md](GOVERNANCE.md) for:

- Decision-making processes
- Maintainer responsibilities
- Conflict resolution procedures

---

## Recognition

Contributors are recognized in:

1. **CONTRIBUTORS.md**: All contributors listed
2. **Release Notes**: Significant contributions acknowledged
3. **Documentation**: Authors credited for major features

Thank you for contributing to UCID and helping advance urban data science.

---

Copyright 2026 UCID Foundation. All rights reserved.

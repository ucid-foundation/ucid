# Contributing to UCID

## Document Information

| Field | Value |
|-------|-------|
| Document Title | UCID Contribution Guidelines |
| Version | 1.0.5 |
| Last Updated | 2026-01-16 |
| Maintainer | UCID Foundation |

---

## Table of Contents

1. [Welcome](#welcome)
2. [Code of Conduct](#code-of-conduct)
3. [Getting Started](#getting-started)
4. [Development Environment](#development-environment)
5. [Contribution Types](#contribution-types)
6. [Pull Request Process](#pull-request-process)
7. [Coding Standards](#coding-standards)
8. [Testing Guidelines](#testing-guidelines)
9. [Documentation Guidelines](#documentation-guidelines)
10. [Commit Guidelines](#commit-guidelines)
11. [Review Process](#review-process)
12. [Release Process](#release-process)
13. [Community](#community)

---

## Welcome

Thank you for your interest in contributing to UCID (Urban Context Identifier). We welcome contributions from everyone, whether you are fixing a typo, improving documentation, or implementing new features.

### Library Statistics

| Metric | Value |
|--------|-------|
| Total Cities | 405 |
| Countries | 23 |
| Contributors | 50+ |
| Test Coverage | 85%+ |

### Ways to Contribute

| Type | Description |
|------|-------------|
| Bug Reports | Report issues you encounter |
| Bug Fixes | Fix reported issues |
| Features | Implement new functionality |
| Documentation | Improve or add documentation |
| Tests | Add or improve tests |
| Reviews | Review pull requests |
| Support | Help others in discussions |

---

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

### Key Points

- Be respectful and inclusive
- Welcome newcomers
- Focus on constructive feedback
- Assume good intentions

---

## Getting Started

### Prerequisites

| Software | Version | Purpose |
|----------|---------|---------|
| Python | 3.11+ | Runtime |
| Git | 2.30+ | Version control |
| pip | 23.0+ | Package manager |

### Fork and Clone

```bash
# Fork the repository on GitHub
# Then clone your fork
git clone https://github.com/YOUR_USERNAME/ucid.git
cd ucid

# Add upstream remote
git remote add upstream https://github.com/ucid-foundation/ucid.git
```

### Create a Branch

```bash
# Update your local main
git checkout main
git pull upstream main

# Create a feature branch
git checkout -b feature/your-feature-name
```

### Branch Naming

| Type | Pattern | Example |
|------|---------|---------|
| Feature | feature/description | feature/add-climate-context |
| Bug Fix | fix/description | fix/parser-validation |
| Documentation | docs/description | docs/api-reference |
| Refactor | refactor/description | refactor/context-base |
| Test | test/description | test/add-integration-tests |

---

## Development Environment

### Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -e ".[dev,test,lint]"

# Install pre-commit hooks
pre-commit install
```

### Verify Installation

```bash
# Run tests
pytest tests/ -v

# Run linting
ruff check src/

# Run type checking
mypy src/ucid
```

### Development Tools

| Tool | Purpose | Command |
|------|---------|---------|
| pytest | Testing | `pytest tests/` |
| ruff | Linting | `ruff check src/` |
| ruff | Formatting | `ruff format src/` |
| mypy | Type checking | `mypy src/ucid` |
| pre-commit | Git hooks | `pre-commit run --all-files` |

### Makefile Commands

```bash
make install     # Install dependencies
make test        # Run tests
make test-cov    # Run tests with coverage
make lint        # Run linter
make format      # Format code
make type-check  # Run type checker
make docs        # Build documentation
make clean       # Clean build artifacts
```

---

## Contribution Types

### Bug Reports

When reporting bugs, please include:

1. **Python version** (`python --version`)
2. **UCID version** (`python -c "import ucid; print(ucid.__version__)"`)
3. **Operating system**
4. **Minimal reproducible example**
5. **Expected behavior**
6. **Actual behavior**
7. **Error messages** (full traceback)

#### Bug Report Template

```markdown
## Bug Description
[Clear description of the bug]

## Environment
- Python version: 3.12.0
- UCID version: 1.0.5
- OS: Ubuntu 22.04

## Reproduction Steps
1. Step 1
2. Step 2
3. Step 3

## Expected Behavior
[What should happen]

## Actual Behavior
[What actually happens]

## Error Message
```
[Full error traceback]
```

## Additional Context
[Any other relevant information]
```

### Feature Requests

For feature requests, please include:

1. **Use case** (why is this feature needed)
2. **Proposed solution** (how it might work)
3. **Alternatives considered**
4. **Additional context**

### Documentation

Documentation contributions are highly valued:

- Fix typos and grammatical errors
- Improve explanations
- Add examples
- Update outdated information
- Translate documentation

### Code Contributions

Before starting work on a significant change:

1. Check existing issues and PRs
2. Open an issue for discussion
3. Wait for feedback from maintainers
4. Reference the issue in your PR

---

## Pull Request Process

### Before Submitting

```bash
# Update from upstream
git fetch upstream
git rebase upstream/main

# Run all checks
make format
make lint
make type-check
make test

# Commit changes
git add .
git commit -m "feat: add new feature"
```

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] All tests pass
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] Changelog entry added (if applicable)
- [ ] Commits follow conventional format
- [ ] PR description is complete

### PR Template

```markdown
## Description
[Clear description of changes]

## Related Issues
Fixes #123

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] All tests pass

## Checklist
- [ ] My code follows the style guidelines
- [ ] I have performed a self-review
- [ ] I have commented my code where necessary
- [ ] I have updated the documentation
- [ ] My changes generate no new warnings
```

### Review Response

When reviewers request changes:

1. Address all comments
2. Push new commits (don't force-push during review)
3. Reply to each comment
4. Re-request review when ready

---

## Coding Standards

### Style Guide

UCID follows these style guidelines:

| Aspect | Standard |
|--------|----------|
| Formatter | Ruff |
| Linter | Ruff |
| Max line length | 88 characters |
| Import sort | isort-compatible |
| Docstrings | Google style |
| Type hints | Required for all public functions |

### Code Example

```python
# Copyright 2026 UCID Foundation
# Licensed under EUPL-1.2

"""Module description.

This module provides functionality for...
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

from ucid.core.models import UCID


def create_example(
    city: str,
    lat: float,
    lon: float,
    *,
    context: str = "15MIN",
) -> UCID:
    """Create an example UCID.

    Args:
        city: Three-letter city code.
        lat: Latitude in decimal degrees.
        lon: Longitude in decimal degrees.
        context: Context algorithm to use.

    Returns:
        A new UCID instance.

    Raises:
        ValueError: If coordinates are invalid.

    Example:
        >>> ucid = create_example("IST", 41.015, 28.979)
        >>> print(ucid.city)
        IST
    """
    if not -90 <= lat <= 90:
        msg = f"Invalid latitude: {lat}"
        raise ValueError(msg)

    # Implementation here
    ...
```

### Type Hints

All public functions must have type hints:

```python
from typing import Any

def process_data(
    data: dict[str, Any],
    *,
    validate: bool = True,
) -> list[str]:
    """Process data and return results."""
    ...
```

---

## Testing Guidelines

### Test Structure

```
tests/
├── conftest.py           # Shared fixtures
├── unit/                 # Unit tests
│   ├── test_parser.py
│   └── test_validator.py
├── integration/          # Integration tests
│   └── test_api.py
└── performance/          # Performance tests
    └── test_benchmark.py
```

### Writing Tests

```python
"""Tests for the parser module."""

import pytest

from ucid.core.parser import parse_ucid
from ucid.core.errors import UCIDParseError


class TestParseUCID:
    """Tests for parse_ucid function."""

    def test_parse_valid_ucid(self) -> None:
        """Test parsing a valid UCID string."""
        ucid_str = "UCID-V1:IST:+41.015:+28.979:9:..."
        result = parse_ucid(ucid_str)

        assert result.city == "IST"
        assert result.lat == 41.015

    def test_parse_invalid_raises_error(self) -> None:
        """Test that invalid input raises UCIDParseError."""
        with pytest.raises(UCIDParseError):
            parse_ucid("invalid")

    @pytest.mark.parametrize("grade", ["A", "B", "C", "D", "F"])
    def test_parse_all_grades(self, grade: str) -> None:
        """Test parsing UCIDs with all valid grades."""
        ...
```

### Running Tests

```bash
# All tests
pytest tests/ -v

# Specific file
pytest tests/unit/test_parser.py -v

# With coverage
pytest tests/ --cov=ucid --cov-report=html

# Only fast tests
pytest tests/ -m "not slow"
```

---

## Documentation Guidelines

### Docstring Format

Use Google-style docstrings:

```python
def example_function(param1: str, param2: int) -> bool:
    """Short description of function.

    Longer description if needed, explaining what the function
    does in more detail.

    Args:
        param1: Description of param1.
        param2: Description of param2.

    Returns:
        Description of return value.

    Raises:
        ValueError: When param1 is empty.

    Example:
        >>> result = example_function("test", 42)
        >>> print(result)
        True
    """
```

### Markdown Files

- Use consistent heading hierarchy
- Include table of contents for long documents
- Use tables for structured information
- Include code examples
- Use Mermaid for diagrams

---

## Commit Guidelines

### Conventional Commits

Use the Conventional Commits format:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Commit Types

| Type | Description |
|------|-------------|
| feat | New feature |
| fix | Bug fix |
| docs | Documentation only |
| style | Formatting, no code change |
| refactor | Code change, no feature/fix |
| perf | Performance improvement |
| test | Adding/updating tests |
| chore | Maintenance tasks |
| ci | CI/CD changes |

### Examples

```
feat(parser): add support for custom flags

fix(validator): handle edge case for week 53

docs(readme): update installation instructions

test(contexts): add tests for WALK context
```

---

## Review Process

### What Reviewers Look For

| Aspect | Criteria |
|--------|----------|
| Correctness | Does the code work correctly? |
| Tests | Are there adequate tests? |
| Style | Does it follow guidelines? |
| Documentation | Is it well documented? |
| Performance | Any performance issues? |
| Security | Any security concerns? |

### Responding to Reviews

1. Be open to feedback
2. Ask for clarification if needed
3. Discuss alternatives constructively
4. Push updates as new commits

---

## Release Process

### Version Numbering

UCID uses Semantic Versioning:

- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes (backward compatible)

### Release Checklist

1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Create release branch
4. Run full test suite
5. Build and test package
6. Create GitHub release
7. Publish to PyPI

---

## Community

### Getting Help

| Channel | Purpose |
|---------|---------|
| GitHub Issues | Bug reports, features |
| GitHub Discussions | Questions, ideas |
| Discord | Real-time chat |
| Mailing List | Announcements |

### Contact

| Contact | Email |
|---------|-------|
| General | contact@ucid.org |
| Security | security@ucid.org |
| Conduct | conduct@ucid.org |

---

## Recognition

Contributors are recognized in:

- CONTRIBUTORS.md file
- Release notes
- GitHub contributors page

---

## License

By contributing, you agree that your contributions will be licensed under EUPL-1.2.

---

Copyright 2026 UCID Foundation. All rights reserved.
Licensed under EUPL-1.2.

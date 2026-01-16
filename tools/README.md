# Tools Directory

## Document Information

| Field | Value |
|-------|-------|
| Directory | tools |
| Purpose | Development and automation tools |
| Last Updated | 2026-01-16 |
| Maintainer | UCID Foundation |
| License | EUPL-1.2 |

---

## Overview

This directory contains development, automation, and maintenance tools for the UCID library. These tools support the development workflow, code quality, release management, and operational tasks.

---

## Directory Structure

```
tools/
├── README.md              # This documentation file
├── check_licenses.py      # License compliance checker
├── generate_docs.py       # Documentation generator
├── update_version.py      # Version management tool
├── validate_data.py       # Data validation tool
├── sync_registry.py       # City registry synchronization
├── run_benchmarks.py      # Benchmark runner
└── release_notes.py       # Release notes generator
```

---

## Tools Overview

| Tool | Purpose | Usage |
|------|---------|-------|
| check_licenses.py | Verify license compliance | `python tools/check_licenses.py` |
| generate_docs.py | Generate API documentation | `python tools/generate_docs.py` |
| update_version.py | Update version numbers | `python tools/update_version.py 1.0.6` |
| validate_data.py | Validate JSON data files | `python tools/validate_data.py` |
| sync_registry.py | Sync city registry data | `python tools/sync_registry.py` |
| run_benchmarks.py | Execute performance benchmarks | `python tools/run_benchmarks.py` |
| release_notes.py | Generate release notes | `python tools/release_notes.py` |

---

## Tool Descriptions

### check_licenses.py

Scans the repository for license compliance issues:

- Verifies all source files have proper license headers
- Checks third-party dependency licenses for compatibility
- Generates compliance report

**Usage:**

```bash
python tools/check_licenses.py --report compliance_report.json
```

**Output:**
- Console summary
- JSON report with detailed findings

### generate_docs.py

Generates API documentation from source code:

- Extracts docstrings from Python modules
- Generates Markdown documentation
- Creates API reference pages

**Usage:**

```bash
python tools/generate_docs.py --output docs/api/
```

### update_version.py

Manages version numbers across the project:

- Updates `pyproject.toml`
- Updates `__init__.py`
- Updates `VERSION` file
- Validates semantic versioning

**Usage:**

```bash
python tools/update_version.py 1.0.6
python tools/update_version.py --bump patch
python tools/update_version.py --bump minor
python tools/update_version.py --bump major
```

### validate_data.py

Validates JSON data files in the data/ directory:

- Schema validation for cities.json
- Schema validation for contexts.json
- Schema validation for grading.json
- Integrity checks

**Usage:**

```bash
python tools/validate_data.py
python tools/validate_data.py --file data/cities.json
```

### sync_registry.py

Synchronizes city registry with external sources:

- Fetches population data updates
- Updates timezone information
- Validates coordinate accuracy

**Usage:**

```bash
python tools/sync_registry.py --dry-run
python tools/sync_registry.py --apply
```

### run_benchmarks.py

Executes performance benchmarks:

- CREATE operation benchmarks
- PARSE operation benchmarks
- VALIDATE operation benchmarks
- Batch processing benchmarks

**Usage:**

```bash
python tools/run_benchmarks.py
python tools/run_benchmarks.py --iterations 100000
python tools/run_benchmarks.py --output benchmarks/results/latest.json
```

### release_notes.py

Generates release notes from git history:

- Extracts conventional commits
- Groups by type (feat, fix, docs, etc.)
- Generates Markdown release notes

**Usage:**

```bash
python tools/release_notes.py --version 1.0.6
python tools/release_notes.py --from v1.0.5 --to v1.0.6
```

---

## Statistics

| Metric | Value |
|--------|-------|
| Total Tools | 7 |
| Python Scripts | 7 |
| Lines of Code | 2,000+ |

---

## Development Guidelines

### Adding New Tools

1. Create the tool in `tools/` directory
2. Follow Google OSS Python style guide
3. Include EUPL-1.2 license header
4. Add comprehensive docstrings
5. Include argument parsing with `argparse`
6. Add entry to this README

### Tool Structure

```python
#!/usr/bin/env python3
# Copyright 2026 UCID Foundation
# Licensed under EUPL-1.2

"""Tool description.

Detailed description of what the tool does.

Usage:
    python tools/tool_name.py [options]

Example:
    python tools/tool_name.py --option value
"""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    # Add arguments
    args = parser.parse_args(argv)
    
    # Tool logic
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## Dependencies

Tools may require additional dependencies:

```bash
pip install -e ".[dev]"
```

---

## Makefile Integration

Tools are integrated with the project Makefile:

```bash
make check-licenses
make generate-docs
make benchmarks
make release-notes
```

---

## References

- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
- [UCID Contributing Guide](../CONTRIBUTING.md)
- [Semantic Versioning](https://semver.org/)

---

Copyright 2026 UCID Foundation. All rights reserved.
Licensed under EUPL-1.2.

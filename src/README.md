# UCID Source Code

This directory contains the UCID library source code.

## Structure

```
src/ucid/
├── __init__.py          # Public API exports
├── core/                # Core functionality
│   ├── parser.py        # UCID parsing
│   ├── validator.py     # Validation logic
│   ├── creator.py       # UCID creation
│   ├── models.py        # Data models
│   └── errors.py        # Exception classes
├── contexts/            # Context algorithms
│   ├── base.py          # Base context class
│   ├── fifteen_min.py   # 15MIN context
│   ├── transit.py       # TRANSIT context
│   └── walk.py          # WALK context
├── spatial/             # Spatial operations
│   ├── h3_utils.py      # H3 utilities
│   └── geometry.py      # Geometry operations
├── data/                # Data access
│   ├── registry.py      # City registry
│   └── sources.py       # External data sources
├── api/                 # REST API
│   ├── app.py           # FastAPI application
│   └── routes.py        # API routes
└── cli/                 # Command-line interface
    └── main.py          # CLI entry point
```

## Statistics

| Metric | Value |
|--------|-------|
| Python files | 114 |
| Lines of code | 12,717 |

---

Copyright 2026 UCID Foundation. Licensed under EUPL-1.2.

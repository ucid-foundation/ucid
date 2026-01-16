# UCID Documentation

Welcome to the UCID (Urban Context Identifier) documentation.

## Overview

UCID is a standardized, temporal identifier system and Python library for comprehensive urban context analysis. It provides a universal key for joining disparate urban datasets across global cities.

## Quick Start

```python
from ucid import create_ucid, parse_ucid

# Create a UCID
ucid = create_ucid(
    city="IST",
    lat=41.015,
    lon=28.979,
    context="15MIN"
)

print(ucid)
# UCID-V1:IST:+41.015:+28.979:9:891f2ed6df7ffff:2026W03T00:15MIN:B:0.72
```

## Features

- **405 Cities**: Coverage across 24 countries
- **8 Context Types**: 15MIN, TRANSIT, WALK, CLIMATE, EQUITY, VITALITY, SAFETY, NONE
- **High Performance**: 127,000+ CREATE operations/second
- **H3 Integration**: Hexagonal hierarchical spatial indexing

## Installation

```bash
pip install ucid
```

## Documentation Sections

- [Getting Started](getting-started/installation.md) - Installation and quick start
- [User Guide](user-guide/overview.md) - Detailed usage guide
- [API Reference](api/index.md) - API documentation
- [Contributing](contributing.md) - How to contribute

## License

UCID is licensed under the EUPL-1.2 license.

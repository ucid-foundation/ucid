# UCID Installation Guide

## Quick Install

```bash
pip install ucid
```

## Requirements

| Requirement | Version |
|-------------|---------|
| Python | 3.11, 3.12, 3.13 |
| pip | 21.0+ |
| OS | Linux, macOS, Windows |

## Installation Options

### Basic Installation

```bash
pip install ucid
```

### With All Features

```bash
pip install "ucid[all]"
```

### With Context Algorithms

```bash
pip install "ucid[contexts]"
```

### With REST API

```bash
pip install "ucid[api]"
```

### Development Installation

```bash
git clone https://github.com/ucid-foundation/ucid.git
cd ucid
pip install -e ".[dev]"
```

## Verification

```python
import ucid
print(f"Version: {ucid.__version__}")
print(f"Cities: {len(ucid.list_cities())}")
```

## Troubleshooting

### H3 Installation Issues

If H3 fails to install:

```bash
pip install --upgrade pip
pip install h3
```

### Windows Issues

```bash
pip install --upgrade setuptools wheel
pip install ucid
```

## Uninstall

```bash
pip uninstall ucid
```

---

Copyright 2026 UCID Foundation. Licensed under EUPL-1.2.

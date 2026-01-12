# UCID Examples

This directory contains comprehensive example scripts demonstrating various
UCID use cases, from basic operations to advanced analysis workflows.

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Available Examples](#available-examples)
4. [Quick Start](#quick-start)
5. [Example Details](#example-details)
   - [Quickstart](#quickstart)
   - [Batch Processing](#batch-processing)
   - [Multi-Context Analysis](#multi-context-analysis)
   - [GeoJSON Export](#geojson-export)
   - [Demo Script](#demo-script)
6. [Expected Output](#expected-output)
7. [Integration Patterns](#integration-patterns)
8. [Best Practices](#best-practices)
9. [Troubleshooting](#troubleshooting)
10. [Additional Resources](#additional-resources)

---

## Overview

The UCID examples demonstrate practical applications of the Urban Context
Identifier system. Each example is self-contained and can be run independently.
The examples progress from basic usage to advanced integration patterns.

### Learning Path

For new users, we recommend following this progression:

1. **quickstart.py** - Learn basic UCID operations
2. **batch_processing.py** - Scale to multiple locations
3. **multi_context.py** - Explore different analysis contexts
4. **geojson_export.py** - Export data for visualization
5. **demo.py** - See all features together

---

## Prerequisites

### System Requirements

- Python 3.11 or later
- pip package manager
- 4GB RAM minimum (for batch processing)
- Internet connection (for data downloads)

### Installation

```bash
# Install UCID
pip install ucid

# Install optional dependencies for full functionality
pip install ucid[all]

# Or install specific extras
pip install ucid[geo]      # GeoPandas, Shapely
pip install ucid[viz]      # Matplotlib, Folium
pip install ucid[ml]       # scikit-learn, LightGBM
```

### Verify Installation

```python
import ucid
print(f"UCID version: {ucid.__version__}")
```

---

## Available Examples

| Example | Description | Difficulty | Time |
|---------|-------------|------------|------|
| [quickstart.py](quickstart.py) | Basic UCID creation, parsing, validation | Beginner | 2 min |
| [batch_processing.py](batch_processing.py) | Process multiple locations efficiently | Beginner | 5 min |
| [multi_context.py](multi_context.py) | Analyze with different urban contexts | Intermediate | 5 min |
| [geojson_export.py](geojson_export.py) | Export UCID data for mapping | Intermediate | 5 min |
| [demo.py](demo.py) | Comprehensive feature demonstration | Advanced | 10 min |

---

## Quick Start

### Run Your First Example

```bash
# Navigate to examples directory
cd examples

# Run the quickstart example
python quickstart.py
```

### Run All Examples

```bash
# Run all examples in sequence
for script in quickstart.py batch_processing.py multi_context.py geojson_export.py demo.py; do
    echo "Running $script..."
    python $script
    echo ""
done
```

---

## Example Details

### Quickstart

**File:** `quickstart.py`

The quickstart example demonstrates fundamental UCID operations:

- Creating a UCID from coordinates
- Validating UCID strings
- Parsing UCID components
- Extracting geographic coordinates

**Key Concepts:**

```python
from ucid import create_ucid, parse_ucid, is_valid_ucid

# Create a UCID
ucid = create_ucid(
    city="IST",
    lat=41.0082,
    lon=28.9784,
    timestamp="2026W02T14",
    context="15MIN",
)

# Parse components
parsed = parse_ucid(str(ucid))
print(f"City: {parsed.city}")
print(f"Score: {parsed.score}")
```

**Output:**

```
============================================================
UCID Quickstart Example
============================================================

1. Creating a UCID for Istanbul...
   Created: UCID:V1:IST:8a1fb46622dffff:2026W02T14:15MIN:72:B:95

2. Validating UCIDs...
   Valid UCID: True
   Invalid string: False

3. Parsing the UCID...
   City: IST
   H3 Index: 8a1fb46622dffff
   Score: 72
   Grade: B
```

---

### Batch Processing

**File:** `batch_processing.py`

Process multiple locations efficiently using pandas DataFrames:

- Generate sample location data
- Create UCIDs in batch
- Calculate statistics
- Analyze grade distribution

**Key Concepts:**

```python
import pandas as pd
from ucid import create_ucid, parse_ucid

# Process many locations
results = []
for _, row in locations_df.iterrows():
    ucid = create_ucid(
        city="IST",
        lat=row["lat"],
        lon=row["lon"],
        timestamp="2026W02T14",
        context="15MIN",
    )
    results.append({"ucid": str(ucid), "score": parse_ucid(str(ucid)).score})

results_df = pd.DataFrame(results)
print(f"Mean score: {results_df['score'].mean():.1f}")
```

**Performance Tips:**

- Process in batches of 1000-10000 for optimal memory usage
- Use multiprocessing for large datasets
- Pre-filter invalid coordinates before processing

---

### Multi-Context Analysis

**File:** `multi_context.py`

Analyze locations using multiple urban contexts:

- 15MIN (15-minute city accessibility)
- TRANSIT (public transport access)
- CLIMATE (environmental factors)
- WALK (walkability)
- VITALITY (neighborhood liveliness)
- EQUITY (service distribution)

**Key Concepts:**

```python
from ucid.contexts import (
    FifteenMinContext,
    TransitContext,
    ClimateContext,
)

# Analyze with different contexts
contexts = ["15MIN", "TRANSIT", "CLIMATE", "WALK", "VITALITY", "EQUITY"]

for context_name in contexts:
    ucid = create_ucid(
        city="IST",
        lat=41.0370,
        lon=28.9850,
        context=context_name,
    )
    parsed = parse_ucid(str(ucid))
    print(f"{context_name}: {parsed.score}/100")
```

**Context Descriptions:**

| Context | Description | Key Metrics |
|---------|-------------|-------------|
| 15MIN | 15-minute city score | Amenity accessibility |
| TRANSIT | Public transport access | Stop density, frequency |
| CLIMATE | Environmental quality | Green cover, heat islands |
| WALK | Walkability | Street connectivity |
| VITALITY | Urban vibrancy | POI diversity |
| EQUITY | Service distribution | Access equality |

---

### GeoJSON Export

**File:** `geojson_export.py`

Export UCID data for use with mapping libraries:

- Generate grid of UCIDs
- Export to GeoJSON format
- Optional GeoPackage export
- Web map integration

**Key Concepts:**

```python
import json

# Create GeoJSON feature
feature = {
    "type": "Feature",
    "geometry": {
        "type": "Point",
        "coordinates": [lon, lat],
    },
    "properties": {
        "ucid": str(ucid),
        "score": parsed.score,
        "grade": parsed.grade,
    },
}

# Write GeoJSON file
with open("output.geojson", "w") as f:
    json.dump(geojson, f, indent=2)
```

**Output Files:**

- `ucid_grid.geojson` - GeoJSON for web mapping
- `ucid_grid.gpkg` - GeoPackage for GIS software

**Web Map Integration:**

```javascript
// Leaflet.js example
fetch('ucid_grid.geojson')
  .then(response => response.json())
  .then(data => {
    L.geoJSON(data, {
      pointToLayer: (feature, latlng) => {
        return L.circleMarker(latlng, {
          radius: 8,
          fillColor: getColor(feature.properties.score),
          fillOpacity: 0.8,
        });
      }
    }).addTo(map);
  });
```

---

### Demo Script

**File:** `demo.py`

Comprehensive demonstration of all UCID capabilities:

- UCID creation and parsing
- Spatial operations with H3
- Visualization theming
- Integration examples

This script provides a complete overview suitable for presentations
and learning the full feature set.

---

## Expected Output

### Score Interpretation

| Score Range | Grade | Description |
|-------------|-------|-------------|
| 90-100 | A | Excellent |
| 80-89 | B | Good |
| 70-79 | C | Average |
| 60-69 | D | Below Average |
| 0-59 | F | Poor |

### Confidence Levels

| Confidence | Interpretation |
|------------|----------------|
| 90-100% | High confidence, reliable data |
| 70-89% | Moderate confidence, some uncertainty |
| 50-69% | Low confidence, limited data |
| 0-49% | Very low confidence, sparse data |

---

## Integration Patterns

### Web API Integration

```python
import requests

def get_ucid_score(lat, lon, city="IST"):
    """Call UCID API for score."""
    response = requests.post(
        "https://api.ucid.org/v1/score",
        json={"lat": lat, "lon": lon, "city": city},
    )
    return response.json()
```

### Database Storage

```python
import sqlalchemy as sa

# Store UCID in PostgreSQL
engine = sa.create_engine("postgresql://localhost/ucid_db")
with engine.connect() as conn:
    conn.execute(
        sa.text("INSERT INTO ucid_scores (ucid, score) VALUES (:ucid, :score)"),
        {"ucid": str(ucid), "score": parsed.score},
    )
```

### Dashboard Integration

```python
import streamlit as st

st.title("UCID Dashboard")

lat = st.number_input("Latitude", value=41.0082)
lon = st.number_input("Longitude", value=28.9784)

if st.button("Calculate Score"):
    ucid = create_ucid(city="IST", lat=lat, lon=lon)
    parsed = parse_ucid(str(ucid))
    st.metric("Score", parsed.score, parsed.grade)
```

---

## Best Practices

### Performance Optimization

1. **Batch Processing**: Process locations in batches rather than one at a time
2. **Caching**: Cache frequently accessed UCID scores
3. **Async Operations**: Use async I/O for network operations
4. **Memory Management**: Clear large DataFrames when no longer needed

### Error Handling

```python
from ucid.core.errors import UCIDValidationError, UCIDParseError

try:
    ucid = create_ucid(city="IST", lat=lat, lon=lon)
except UCIDValidationError as e:
    print(f"Validation error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Logging

```python
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ucid")

# UCID operations will now log to console
ucid = create_ucid(city="IST", lat=41.0, lon=29.0)
```

---

## Troubleshooting

### Common Issues

**Issue: ImportError when running examples**

```
Solution: Ensure UCID is installed correctly
$ pip install --upgrade ucid
```

**Issue: Network timeout during data download**

```
Solution: Check internet connection and try again
$ python download_sample_data.py --source pdx_gtfs
```

**Issue: Memory error with large batches**

```
Solution: Reduce batch size
# Process in smaller chunks
for chunk in pd.read_csv("locations.csv", chunksize=1000):
    process_batch(chunk)
```

**Issue: Invalid city code error**

```
Solution: Use valid UN/LOCODE city codes
Valid examples: IST, NYC, LON, PAR, TYO
See: https://unece.org/trade/cefact/unlocode-code-list-country-and-territory
```

---

## Additional Resources

### Documentation

- [UCID Documentation](https://ucid.readthedocs.io/)
- [API Reference](https://ucid.readthedocs.io/en/latest/api/)
- [User Guide](https://ucid.readthedocs.io/en/latest/guide/)

### Jupyter Notebooks

For interactive learning, see the [notebooks](../notebooks/) directory:

- `00_ucid_basics.ipynb` - Introduction to UCID
- `01_citygrid_scan_basics.ipynb` - City-wide analysis
- `02_15min_city_isochrones.ipynb` - 15-minute city analysis

### Community

- [GitHub Discussions](https://github.com/ucid-foundation/ucid/discussions)
- [Issue Tracker](https://github.com/ucid-foundation/ucid/issues)
- [X (Twitter)](https://x.com/ucid_foundation)

### Related Projects

- [H3](https://h3geo.org/) - Hexagonal hierarchical spatial index
- [OSMnx](https://osmnx.readthedocs.io/) - Street network analysis
- [GeoPandas](https://geopandas.org/) - Geospatial data in Python

---

## License

Copyright 2026 UCID Foundation.
Licensed under the European Union Public License (EUPL-1.2).

See [LICENSE](../LICENSE) for the full license text.

---

## Contributing

We welcome contributions to improve these examples!

1. Fork the repository
2. Create a feature branch
3. Add or improve examples
4. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for detailed guidelines.

---

*Last updated: January 2026*

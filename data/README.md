# UCID Sample Data

This directory contains sample data for the UCID (Urban Context Identifier) library.

## Files

### City Registry
- **cities.json** - Registry of 10 major world cities with coordinates, timezones, populations, and bounding boxes

### Contexts
- **contexts.json** - Definitions for 8 urban analysis contexts (15MIN, TRANSIT, CLIMATE, EQUITY, VITALITY, SAFETY, HEALTH, SMART)

### Grading
- **grading.json** - Grade scale definitions (A-F) with score ranges, labels, colors, and descriptions

### Transit
- **transit.json** - Transit type definitions and sample transit stops from major cities

### Samples
- **samples/sample_ucids.json** - 10 example UCID records from cities worldwide

## Usage

```python
import json
from pathlib import Path

# Load cities
data_dir = Path("data")
with open(data_dir / "cities.json") as f:
    cities = json.load(f)

# Access Istanbul data
ist = next(c for c in cities["cities"] if c["code"] == "IST")
print(f"Istanbul: {ist['coordinates']['lat']}, {ist['coordinates']['lon']}")
```

## Data Sources

All sample data is provided by the UCID Foundation under the EUPL-1.2 license.
Data is for demonstration and testing purposes only.

## Contributing

To add new cities or update existing data:
1. Follow the existing JSON schema
2. Ensure all required fields are populated
3. Validate coordinates and bounding boxes
4. Submit a PR with your changes

## License

EUPL-1.2 - European Union Public License

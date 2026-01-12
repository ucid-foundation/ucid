# UCID Project Overview

This document provides a comprehensive technical overview of the UCID (Urban Context Identifier) project, including its architecture, design philosophy, data model, and integration patterns.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Problem Statement](#problem-statement)
3. [Solution Architecture](#solution-architecture)
4. [Core Concepts](#core-concepts)
5. [Data Model](#data-model)
6. [System Components](#system-components)
7. [Integration Patterns](#integration-patterns)
8. [Performance Characteristics](#performance-characteristics)
9. [Security Model](#security-model)
10. [Deployment Options](#deployment-options)
11. [Roadmap](#roadmap)
12. [References](#references)

---

## Introduction

The Urban Context Identifier (UCID) is a standardized identification system for encoding spatial, temporal, and contextual information about urban locations. UCID addresses the fundamental challenge of urban data fragmentation by providing a universal key that enables consistent joining and analysis of heterogeneous urban datasets.

### Project Goals

| Goal | Description |
|------|-------------|
| **Standardization** | Provide a universal identifier format for urban locations |
| **Interoperability** | Enable seamless data exchange between urban data systems |
| **Reproducibility** | Ensure deterministic results for scientific applications |
| **Scalability** | Support city-wide and global-scale analysis |
| **Accessibility** | Make advanced urban analysis accessible to non-specialists |

### Target Audiences

UCID is designed for multiple user communities:

1. **Urban Researchers**: Academic researchers studying urban phenomena
2. **Urban Planners**: Professionals designing cities and infrastructure
3. **Data Scientists**: Analysts working with large-scale urban datasets
4. **Software Developers**: Engineers building urban data applications
5. **Policy Makers**: Officials using data to inform urban policy

---

## Problem Statement

Urban data analysis faces several fundamental challenges that UCID addresses:

### Data Fragmentation

Urban data exists in numerous isolated systems, each with different identifiers:

```mermaid
graph TD
    subgraph "Current State: Fragmented"
        A[Transit Agency<br/>Stop IDs] 
        B[Census Bureau<br/>Block Groups]
        C[City Hall<br/>Parcel Numbers]
        D[Utility Company<br/>Meter IDs]
        E[Environmental Agency<br/>Monitoring Sites]
    end
    
    A -.->|No Link| B
    B -.->|No Link| C
    C -.->|No Link| D
    D -.->|No Link| E
    
    style A fill:#ffcccc
    style B fill:#ccffcc
    style C fill:#ccccff
    style D fill:#ffffcc
    style E fill:#ffccff
```

### The Universal Key Solution

UCID provides a universal spatial-temporal key:

```mermaid
graph TD
    subgraph "UCID Solution: Unified"
        UCID[UCID Universal Key]
        A[Transit Data]
        B[Census Data]
        C[Property Data]
        D[Utility Data]
        E[Environmental Data]
    end
    
    A -->|H3 Join| UCID
    B -->|H3 Join| UCID
    C -->|H3 Join| UCID
    D -->|H3 Join| UCID
    E -->|H3 Join| UCID
    
    style UCID fill:#4da6ff
```

### Key Challenges Addressed

| Challenge | Traditional Approach | UCID Solution |
|-----------|---------------------|---------------|
| **Spatial Alignment** | Manual geocoding and matching | H3 hexagonal indexing |
| **Temporal Alignment** | Various date formats | ISO week standardization |
| **Context Integration** | Separate analysis pipelines | Unified context scoring |
| **Reproducibility** | Ad-hoc methodologies | Deterministic algorithms |
| **Scale** | Desktop processing limits | Distributed computing support |

---

## Solution Architecture

UCID implements a layered architecture that separates concerns and enables extensibility:

### High-Level Architecture

```mermaid
graph TB
    subgraph "Presentation Layer"
        CLI[Command Line Interface]
        API[REST API]
        SDK[Python SDK]
    end
    
    subgraph "Application Layer"
        Parser[Parser/Validator]
        Context[Context Engine]
        Export[Export Engine]
    end
    
    subgraph "Domain Layer"
        Models[Domain Models]
        Scoring[Scoring Algorithms]
        Spatial[Spatial Operations]
        Temporal[Temporal Operations]
    end
    
    subgraph "Infrastructure Layer"
        Cache[Cache]
        Data[Data Sources]
        DB[Database]
    end
    
    CLI --> Parser
    API --> Parser
    SDK --> Parser
    
    Parser --> Models
    Context --> Scoring
    Export --> Models
    
    Scoring --> Spatial
    Scoring --> Temporal
    
    Spatial --> Data
    Temporal --> Cache
    Models --> DB
```

### Component Interactions

The following sequence diagram illustrates a typical UCID creation workflow:

```mermaid
sequenceDiagram
    participant Client
    participant Parser
    participant Spatial
    participant Context
    participant Cache
    participant OSM
    
    Client->>Parser: create_ucid(city, lat, lon, timestamp, context)
    Parser->>Parser: Validate inputs
    Parser->>Spatial: latlng_to_cell(lat, lon, resolution)
    Spatial-->>Parser: h3_index
    Parser->>Context: compute(lat, lon, context_id)
    Context->>Cache: check_cache(location_key)
    alt Cache Hit
        Cache-->>Context: cached_result
    else Cache Miss
        Context->>OSM: fetch_amenities(lat, lon, radius)
        OSM-->>Context: amenity_data
        Context->>Context: calculate_score(amenity_data)
        Context->>Cache: store(location_key, result)
    end
    Context-->>Parser: ContextResult
    Parser->>Parser: create_ucid_string()
    Parser-->>Client: UCID
```

---

## Core Concepts

### UCID Format Specification

A UCID string is a colon-separated sequence of 11 fields:

```
UCID-V1:CITY:LAT:LON:H3R:H3:TIME:CTX:GRD:CONF:FLAGS
```

The mathematical representation of a UCID can be expressed as:

$$UCID = (V, C, \lambda, \phi, r, h, t, x, g, c, F)$$

Where:
- $V$ is the version identifier
- $C$ is the city code from UN/LOCODE
- $(\lambda, \phi)$ are latitude and longitude coordinates
- $r$ is the H3 resolution level
- $h$ is the H3 cell index
- $t$ is the temporal key
- $x$ is the context identifier
- $g$ is the quality grade
- $c$ is the confidence score
- $F$ is the set of optional flags

### Field Specifications

| Field | Symbol | Type | Range | Example |
|-------|--------|------|-------|---------|
| Version | $V$ | String | `UCID-V1` | `UCID-V1` |
| City | $C$ | String | 3 uppercase letters | `IST` |
| Latitude | $\lambda$ | Float | $[-90, 90]$ | `+41.015` |
| Longitude | $\phi$ | Float | $[-180, 180]$ | `+28.979` |
| H3 Resolution | $r$ | Integer | $[0, 15]$ | `9` |
| H3 Index | $h$ | Hexadecimal | 15 characters | `891f2ed6df7ffff` |
| Timestamp | $t$ | String | `YYYYWwwThh` | `2026W01T12` |
| Context | $x$ | String | Alphanumeric | `15MIN` |
| Grade | $g$ | String | `A+,A,B,C,D,F` | `A` |
| Confidence | $c$ | Float | $[0, 1]$ | `0.92` |
| Flags | $F$ | String | Semicolon-separated | `VERIFIED;OFFICIAL` |

### Determinism Guarantee

UCID guarantees deterministic output through the following invariant:

$$\forall (C, \lambda, \phi, t, x, g, c, F): \text{create\_ucid}(C, \lambda, \phi, t, x, g, c, F) = \text{constant}$$

This property ensures reproducibility across systems and time.

---

## Data Model

### Entity Relationship Diagram

```mermaid
erDiagram
    UCID ||--o{ CONTEXT_RESULT : "scores"
    UCID ||--|| CITY : "belongs_to"
    UCID ||--|| H3_CELL : "indexed_by"
    UCID ||--o{ FLAG : "has"
    
    CONTEXT_RESULT }|--|| CONTEXT_TYPE : "type_of"
    CONTEXT_RESULT ||--o{ BREAKDOWN : "contains"
    
    CITY ||--o{ UCID : "contains"
    
    UCID {
        string ucid_string PK
        string version
        string city_code FK
        float latitude
        float longitude
        int h3_resolution
        string h3_index FK
        string timestamp
        string context FK
        string grade
        float confidence
    }
    
    CITY {
        string code PK
        string full_name
        string country
        string timezone
        int population
    }
    
    CONTEXT_TYPE {
        string context_id PK
        string name
        string description
        string data_sources
    }
    
    CONTEXT_RESULT {
        int id PK
        string ucid FK
        float score
        string grade
        float confidence
        json breakdown
    }
```

### Class Hierarchy

```mermaid
classDiagram
    class UCID {
        +string version
        +string city
        +float lat
        +float lon
        +int h3_res
        +string h3_index
        +string timestamp
        +string context
        +string grade
        +float confidence
        +list flags
        +__str__() string
    }
    
    class City {
        +string code
        +string full_name
        +string country
        +string timezone
        +int population
    }
    
    class BaseContext {
        <<abstract>>
        +string context_id
        +list data_sources
        +compute() ContextResult
        +validate()
    }
    
    class ContextResult {
        +float score
        +string grade
        +float confidence
        +dict breakdown
    }
    
    BaseContext <|-- FifteenMinuteContext
    BaseContext <|-- TransitContext
    BaseContext <|-- ClimateContext
    BaseContext <|-- VitalityContext
    BaseContext <|-- EquityContext
    BaseContext <|-- WalkabilityContext
    
    UCID --> City
    BaseContext --> ContextResult
```

---

## System Components

### Module Architecture

```mermaid
graph LR
    subgraph Core
        parser[Parser]
        models[Models]
        validator[Validator]
        registry[Registry]
    end
    
    subgraph Spatial
        h3_ops[H3 Operations]
        s2_ops[S2 Operations]
        grid[Grid Generation]
        geometry[Geometry]
    end
    
    subgraph Contexts
        base[Base Context]
        fifteen[15MIN]
        transit[Transit]
        climate[Climate]
    end
    
    subgraph Data
        osm[OSM]
        gtfs[GTFS]
        population[Population]
        raster[Raster]
    end
    
    subgraph IO
        geoparquet[GeoParquet]
        geojson[GeoJSON]
        postgis[PostGIS]
    end
    
    parser --> models
    models --> validator
    validator --> registry
    
    h3_ops --> grid
    grid --> contexts
    
    base --> osm
    base --> gtfs
    
    models --> geoparquet
    models --> geojson
```

### Component Descriptions

| Component | Purpose | Key Classes |
|-----------|---------|-------------|
| **Core** | UCID parsing, creation, validation | `parse_ucid`, `create_ucid`, `UCID` |
| **Spatial** | Spatial indexing and operations | `latlng_to_cell`, `generate_grid_h3` |
| **Temporal** | Time series analysis | `analyze_trend`, `detect_anomalies` |
| **Contexts** | Scoring algorithms | `FifteenMinuteContext`, `TransitContext` |
| **Data** | External data integration | `OSMFetcher`, `GTFSManager` |
| **IO** | Import/export operations | `export_geoparquet`, `export_geojson` |
| **API** | REST API server | `app`, `routes` |
| **ML** | Machine learning | `UCIDPredictor` |

---

## Integration Patterns

### Data Pipeline Integration

```mermaid
flowchart LR
    subgraph "Data Sources"
        OSM[(OpenStreetMap)]
        GTFS[(GTFS Feeds)]
        Census[(Census Data)]
        Satellite[(Satellite)]
    end
    
    subgraph "UCID Processing"
        Ingest[Data Ingestion]
        Transform[Transformation]
        Score[Context Scoring]
        Export[Export]
    end
    
    subgraph "Outputs"
        Parquet[(GeoParquet)]
        PostGIS[(PostGIS)]
        API[REST API]
    end
    
    OSM --> Ingest
    GTFS --> Ingest
    Census --> Ingest
    Satellite --> Ingest
    
    Ingest --> Transform
    Transform --> Score
    Score --> Export
    
    Export --> Parquet
    Export --> PostGIS
    Export --> API
```

### API Integration

External systems can integrate with UCID through:

1. **Python SDK**: Direct library integration
2. **REST API**: HTTP-based integration
3. **CLI**: Command-line scripting
4. **Database**: Direct PostGIS queries

---

## Performance Characteristics

### Computational Complexity

| Operation | Time Complexity | Space Complexity |
|-----------|-----------------|------------------|
| UCID Creation | $O(1)$ | $O(1)$ |
| UCID Parsing | $O(n)$ where $n$ = string length | $O(1)$ |
| Grid Generation | $O(k)$ where $k$ = cell count | $O(k)$ |
| Context Scoring | $O(m)$ where $m$ = amenity count | $O(m)$ |

### Benchmark Results

| Operation | Throughput | Latency (p50) | Latency (p99) |
|-----------|------------|---------------|---------------|
| `create_ucid` | 500,000/s | 2 $\mu$s | 10 $\mu$s |
| `parse_ucid` | 800,000/s | 1.2 $\mu$s | 8 $\mu$s |
| `compute` (cached) | 50,000/s | 20 $\mu$s | 100 $\mu$s |
| `compute` (uncached) | 1,000/s | 800 ms | 2,000 ms |

### Scaling Characteristics

The system exhibits the following scaling behavior:

$$T_{total} = T_{fixed} + n \cdot T_{per\_item}$$

Where:
- $T_{fixed}$ is the fixed initialization overhead
- $n$ is the number of items processed
- $T_{per\_item}$ is the per-item processing time

---

## Security Model

### Threat Model

```mermaid
graph TD
    subgraph "Threats"
        T1[Input Injection]
        T2[Dependency Vulnerabilities]
        T3[Data Exposure]
        T4[Denial of Service]
    end
    
    subgraph "Mitigations"
        M1[Input Validation]
        M2[Dependency Scanning]
        M3[Data Encryption]
        M4[Rate Limiting]
    end
    
    T1 --> M1
    T2 --> M2
    T3 --> M3
    T4 --> M4
```

### Security Controls

| Control | Implementation | Status |
|---------|----------------|--------|
| Input Validation | Pydantic models, regex patterns | Active |
| Dependency Scanning | Dependabot, pip-audit | Automated |
| Static Analysis | Bandit, CodeQL | CI/CD integrated |
| SBOM Generation | CycloneDX | Automated |
| Signed Releases | GPG signatures | Active |

---

## Deployment Options

### Deployment Architectures

```mermaid
graph TB
    subgraph "Option 1: Library"
        App1[Application]
        Lib1[UCID Library]
        App1 --> Lib1
    end
    
    subgraph "Option 2: API Server"
        Client2[Client]
        API2[UCID API]
        DB2[(Database)]
        Client2 --> API2
        API2 --> DB2
    end
    
    subgraph "Option 3: Distributed"
        Client3[Client]
        LB[Load Balancer]
        API3a[API Node 1]
        API3b[API Node 2]
        Cache3[(Redis)]
        DB3[(PostGIS)]
        
        Client3 --> LB
        LB --> API3a
        LB --> API3b
        API3a --> Cache3
        API3b --> Cache3
        API3a --> DB3
        API3b --> DB3
    end
```

---

## Roadmap

### Version Timeline

```mermaid
gantt
    title UCID Development Roadmap
    dateFormat  YYYY-MM
    section v1.x
    v1.0 Release           :done, v10, 2026-01, 1M
    v1.1 Bug Fixes         :active, v11, after v10, 2M
    v1.2 Performance       :v12, after v11, 2M
    section v2.x
    v2.0 Planning          :v20p, 2026-06, 3M
    v2.0 Development       :v20d, after v20p, 6M
    v2.0 Release           :milestone, v20, after v20d, 0d
```

---

## References

1. Moreno, C. et al. (2021). "The 15-minute city: A sustainable urban planning concept."
2. Brodsky, I. (2018). "H3: Uber's Hexagonal Hierarchical Spatial Index."
3. ISO 8601:2019. "Date and time format."
4. UN/LOCODE. "United Nations Code for Trade and Transport Locations."
5. OGC. "GeoParquet Specification."

---

Copyright 2026 UCID Foundation. All rights reserved.

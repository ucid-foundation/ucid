# Architecture

This document provides a comprehensive overview of the UCID (Urban Context Identifier) system architecture, including design principles, component structure, and technical decisions.

---

## Table of Contents

1. [Overview](#overview)
2. [Design Principles](#design-principles)
3. [System Architecture](#system-architecture)
4. [Component Architecture](#component-architecture)
5. [Data Architecture](#data-architecture)
6. [API Architecture](#api-architecture)
7. [Deployment Architecture](#deployment-architecture)
8. [Security Architecture](#security-architecture)
9. [Scalability Architecture](#scalability-architecture)
10. [Future Architecture](#future-architecture)

---

## Overview

### High-Level Architecture

UCID is designed as a modular, extensible library for urban context identification and analysis.

```mermaid
graph TB
    subgraph "Client Layer"
        CLI[CLI]
        SDK[Python SDK]
        API[REST API]
    end
    
    subgraph "Core Layer"
        Parser[Parser]
        Validator[Validator]
        Registry[Registry]
    end
    
    subgraph "Context Layer"
        C15M[15MIN]
        CTR[TRANSIT]
        CCL[CLIMATE]
        More[...]
    end
    
    subgraph "Data Layer"
        OSM[OSM]
        GTFS[GTFS]
        Sat[Satellite]
        Pop[Population]
    end
    
    CLI --> Parser
    SDK --> Parser
    API --> Parser
    Parser --> Validator
    Validator --> Registry
    Registry --> C15M
    Registry --> CTR
    Registry --> CCL
    Registry --> More
    C15M --> OSM
    CTR --> GTFS
    CCL --> Sat
```

### Architecture Goals

| Goal | Description | Approach |
|------|-------------|----------|
| **Modularity** | Loose coupling between components | Plugin architecture |
| **Extensibility** | Easy to add new features | Abstract interfaces |
| **Testability** | High test coverage | Dependency injection |
| **Performance** | Fast processing | Caching, lazy loading |
| **Reliability** | Predictable behavior | Comprehensive validation |

---

## Design Principles

### SOLID Principles

| Principle | Application in UCID |
|-----------|---------------------|
| **Single Responsibility** | Each module has one purpose |
| **Open/Closed** | BaseContext for extension |
| **Liskov Substitution** | Context implementations |
| **Interface Segregation** | Focused interfaces |
| **Dependency Inversion** | Inject data sources |

### Domain-Driven Design

```mermaid
graph TD
    subgraph "Domain Model"
        UCID[UCID Entity]
        Context[Context Value Object]
        Score[Score Value Object]
        City[City Entity]
    end
    
    UCID --> Context
    UCID --> City
    Context --> Score
```

### Hexagonal Architecture

```mermaid
graph TB
    subgraph "External"
        REST[REST API]
        CLI2[CLI]
        DB[Database]
        OSM2[OSM API]
    end
    
    subgraph "Adapters"
        APIAdapter[API Adapter]
        CLIAdapter[CLI Adapter]
        DBAdapter[DB Adapter]
        DataAdapter[Data Adapter]
    end
    
    subgraph "Core Domain"
        UseCases[Use Cases]
        Domain[Domain Logic]
    end
    
    REST --> APIAdapter
    CLI2 --> CLIAdapter
    APIAdapter --> UseCases
    CLIAdapter --> UseCases
    UseCases --> Domain
    Domain --> DBAdapter
    Domain --> DataAdapter
    DBAdapter --> DB
    DataAdapter --> OSM2
```

---

## System Architecture

### Module Structure

```
src/ucid/
    __init__.py          # Public API
    core/                # Core functionality
        parser.py        # UCID parsing
        models.py        # Data models
        validation.py    # Input validation
        errors.py        # Exception hierarchy
    contexts/            # Context plugins
        base.py          # Abstract base
        registry.py      # Plugin registry
        fifteen_min.py   # 15MIN context
        transit.py       # TRANSIT context
        climate.py       # CLIMATE context
    spatial/             # Spatial operations
        h3_ops.py        # H3 functions
        grid.py          # Grid generation
        neighbors.py     # Neighbor computation
    data/                # Data integration
        osm.py           # OpenStreetMap
        gtfs.py          # GTFS feeds
        satellite.py     # Satellite imagery
        population.py    # Population data
    io/                  # Input/Output
        formats.py       # Export formats
        geo.py           # Geospatial I/O
    api/                 # REST API
        app.py           # FastAPI app
        routes.py        # API routes
        auth.py          # Authentication
```

### Dependency Graph

```mermaid
graph BT
    core[Core]
    spatial[Spatial]
    data[Data]
    contexts[Contexts]
    io[I/O]
    api[API]
    
    spatial --> core
    data --> core
    data --> spatial
    contexts --> core
    contexts --> spatial
    contexts --> data
    io --> core
    io --> spatial
    api --> core
    api --> contexts
    api --> io
```

---

## Component Architecture

### Core Component

| Module | Responsibility |
|--------|----------------|
| `parser.py` | UCID string parsing and creation |
| `models.py` | Pydantic data models |
| `validation.py` | Input validation rules |
| `errors.py` | Custom exception types |
| `registry.py` | City and context registries |

### Context System

```mermaid
classDiagram
    class BaseContext {
        <<abstract>>
        +context_id: str
        +name: str
        +compute(lat, lon, timestamp)
        +validate(lat, lon)
    }
    
    class FifteenMinContext {
        +compute(lat, lon, timestamp)
        -_fetch_amenities()
        -_calculate_accessibility()
    }
    
    class TransitContext {
        +compute(lat, lon, timestamp)
        -_fetch_gtfs()
        -_calculate_service_level()
    }
    
    BaseContext <|-- FifteenMinContext
    BaseContext <|-- TransitContext
```

### Spatial Component

| Module | Responsibility |
|--------|----------------|
| `h3_ops.py` | H3 index operations |
| `grid.py` | Grid generation |
| `neighbors.py` | K-ring computation |
| `aggregate.py` | Spatial aggregation |

---

## Data Architecture

### Data Flow

```mermaid
flowchart LR
    Sources[Data Sources] --> Fetch[Fetchers]
    Fetch --> Process[Processors]
    Process --> Cache[Cache]
    Cache --> Context[Contexts]
    Context --> Score[Scores]
```

### Caching Strategy

| Layer | Cache Type | TTL |
|-------|------------|-----|
| OSM Data | File/Redis | 24 hours |
| GTFS Data | File | Until feed update |
| Satellite | File | 7 days |
| Scores | Redis | 1 hour |

### Data Models

```python
@dataclass
class UCIDModel:
    prefix: str = "UCID"
    version: str = "V1"
    city: str
    h3_index: str
    timestamp: str
    context: str
    score: int
    grade: str
    confidence: int
    
@dataclass
class ContextResult:
    score: float
    grade: str
    confidence: float
    breakdown: dict[str, float]
    metadata: dict
```

---

## API Architecture

### REST API Design

```mermaid
graph LR
    Client[Client] --> Gateway[API Gateway]
    Gateway --> Auth[Auth]
    Auth --> Rate[Rate Limiter]
    Rate --> Router[Router]
    Router --> Handlers[Handlers]
    Handlers --> Services[Services]
```

### API Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | /v1/ucid/create | Create UCID |
| GET | /v1/ucid/{id} | Get UCID details |
| POST | /v1/ucid/batch | Batch creation |
| GET | /v1/contexts | List contexts |
| POST | /v1/contexts/{id}/score | Score location |
| GET | /v1/grid | Generate grid |

### Authentication

```mermaid
sequenceDiagram
    Client->>API: Request + API Key
    API->>Auth: Validate Key
    Auth->>Redis: Check Key
    Redis-->>Auth: Key Valid
    Auth-->>API: User Context
    API->>Handler: Process Request
    Handler-->>API: Response
    API-->>Client: JSON Response
```

---

## Deployment Architecture

### Container Architecture

```mermaid
graph TB
    subgraph "Load Balancer"
        LB[Nginx]
    end
    
    subgraph "Application"
        API1[API Pod 1]
        API2[API Pod 2]
        API3[API Pod 3]
    end
    
    subgraph "Data"
        Redis[Redis]
        PostgreSQL[PostgreSQL + PostGIS]
    end
    
    LB --> API1
    LB --> API2
    LB --> API3
    API1 --> Redis
    API2 --> Redis
    API3 --> Redis
    API1 --> PostgreSQL
    API2 --> PostgreSQL
    API3 --> PostgreSQL
```

### Kubernetes Deployment

| Resource | Purpose |
|----------|---------|
| Deployment | API pods |
| Service | Internal routing |
| Ingress | External access |
| ConfigMap | Configuration |
| Secret | Credentials |
| HPA | Auto-scaling |

---

## Security Architecture

### Security Layers

| Layer | Mechanism |
|-------|-----------|
| Transport | TLS 1.3 |
| Authentication | API Keys, OAuth2 |
| Authorization | RBAC |
| Input | Validation, Sanitization |
| Data | Encryption at rest |

### Threat Model

```mermaid
graph TD
    subgraph "Threats"
        T1[Injection]
        T2[Auth Bypass]
        T3[Data Exposure]
        T4[DoS]
    end
    
    subgraph "Mitigations"
        M1[Input Validation]
        M2[Secure Auth]
        M3[Encryption]
        M4[Rate Limiting]
    end
    
    T1 --> M1
    T2 --> M2
    T3 --> M3
    T4 --> M4
```

---

## Scalability Architecture

### Horizontal Scaling

| Component | Scaling Strategy |
|-----------|------------------|
| API | Multiple pods |
| Workers | Queue-based |
| Database | Read replicas |
| Cache | Cluster |

### Performance Optimization

| Technique | Benefit |
|-----------|---------|
| Caching | Reduce compute |
| Lazy loading | Reduce memory |
| Batch processing | Improve throughput |
| Connection pooling | Reduce overhead |

---

## Future Architecture

### Planned Improvements

| Area | Improvement |
|------|-------------|
| Async | Full async support |
| Streaming | Real-time updates |
| Federation | Distributed compute |
| ML | AI-enhanced scoring |

---

## References

- [H3 Documentation](https://h3geo.org/)
- [PostGIS](https://postgis.net/)
- [FastAPI](https://fastapi.tiangolo.com/)
- [Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)

---

Copyright 2026 UCID Foundation. All rights reserved.

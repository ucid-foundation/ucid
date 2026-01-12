# PostGIS Database Integration

This document provides documentation for integrating UCID with PostGIS for spatial database operations and persistent storage.

---

## Table of Contents

1. [Overview](#overview)
2. [Schema Design](#schema-design)
3. [Connection Management](#connection-management)
4. [CRUD Operations](#crud-operations)
5. [Spatial Queries](#spatial-queries)
6. [Indexing](#indexing)
7. [Bulk Operations](#bulk-operations)
8. [Implementation](#implementation)
9. [Performance](#performance)
10. [Administration](#administration)

---

## Overview

PostGIS extends PostgreSQL with spatial data types and functions, providing robust storage and querying for UCID data at scale.

### Architecture

```mermaid
graph TD
    subgraph "Application Layer"
        UCID[UCID Library]
        API[FastAPI]
    end
    
    subgraph "Database Layer"
        PG[PostgreSQL 16]
        PostGIS[PostGIS 3.4]
        H3PG[H3-pg Extension]
    end
    
    subgraph "Storage"
        Tables[UCID Tables]
        Indices[Spatial Indices]
    end
    
    UCID --> PG
    API --> PG
    PG --> PostGIS
    PG --> H3PG
    PostGIS --> Tables
    H3PG --> Tables
    Tables --> Indices
```

### Required Extensions

| Extension | Version | Purpose |
|-----------|---------|---------|
| postgis | 3.4+ | Spatial types and functions |
| h3 | 4.1+ | H3 indexing |
| timescaledb | 2.x | Time-series (optional) |

---

## Schema Design

### Core Tables

```sql
-- Cities table
CREATE TABLE cities (
    code VARCHAR(3) PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL,
    country VARCHAR(2) NOT NULL,
    timezone VARCHAR(50) NOT NULL,
    population INTEGER,
    bounds GEOMETRY(POLYGON, 4326)
);

-- UCID scores table
CREATE TABLE ucid_scores (
    id BIGSERIAL PRIMARY KEY,
    ucid_string VARCHAR(255) UNIQUE NOT NULL,
    city_code VARCHAR(3) REFERENCES cities(code),
    h3_index H3INDEX NOT NULL,
    timestamp VARCHAR(10) NOT NULL,
    context VARCHAR(16) NOT NULL,
    score NUMERIC(5,2) NOT NULL,
    grade VARCHAR(2) NOT NULL,
    confidence NUMERIC(3,2) NOT NULL,
    breakdown JSONB,
    location GEOMETRY(POINT, 4326) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Context definitions
CREATE TABLE contexts (
    context_id VARCHAR(16) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    data_sources TEXT[],
    weights JSONB
);
```

### Entity Relationship Diagram

```mermaid
erDiagram
    CITIES ||--o{ UCID_SCORES : contains
    CONTEXTS ||--o{ UCID_SCORES : defines
    
    CITIES {
        varchar code PK
        varchar full_name
        varchar country
        varchar timezone
        int population
        geometry bounds
    }
    
    UCID_SCORES {
        bigint id PK
        varchar ucid_string UK
        varchar city_code FK
        h3index h3_index
        varchar timestamp
        varchar context FK
        numeric score
        varchar grade
        numeric confidence
        jsonb breakdown
        geometry location
    }
    
    CONTEXTS {
        varchar context_id PK
        varchar name
        text description
        jsonb weights
    }
```

### Partitioning

Partition by city for large datasets:

```sql
CREATE TABLE ucid_scores (
    -- columns as above
) PARTITION BY LIST (city_code);

CREATE TABLE ucid_scores_ist PARTITION OF ucid_scores
    FOR VALUES IN ('IST');

CREATE TABLE ucid_scores_nyc PARTITION OF ucid_scores
    FOR VALUES IN ('NYC');
```

---

## Connection Management

### SQLAlchemy Setup

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from geoalchemy2 import Geometry

DATABASE_URL = "postgresql+psycopg2://user:pass@localhost:5432/ucid"

engine = create_engine(
    DATABASE_URL,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

### Connection Pooling

| Parameter | Value | Description |
|-----------|-------|-------------|
| pool_size | 5 | Permanent connections |
| max_overflow | 10 | Temporary connections |
| pool_timeout | 30 | Wait for connection |
| pool_pre_ping | True | Check connection health |

---

## CRUD Operations

### Create

```python
from ucid.db import UCIDRepository

repo = UCIDRepository(session)

# Insert single UCID
ucid = create_ucid(city="IST", lat=41.015, lon=28.979, ...)
repo.insert(ucid)

# Bulk insert
repo.insert_many(ucids, batch_size=1000)
```

### Read

```python
# Get by UCID string
ucid = repo.get_by_string("UCID-V1:IST:+41.015:...")

# Get by H3 cell
ucids = repo.get_by_h3("891f2ed6df7ffff")

# Get by city and context
ucids = repo.find(city="IST", context="15MIN", limit=100)
```

### Update

```python
# Update score
repo.update_score(ucid_string, new_score=85.5, new_grade="A")

# Bulk update
repo.update_many(
    filter={"city": "IST", "context": "15MIN"},
    update={"updated_at": datetime.now()},
)
```

### Delete

```python
# Delete by UCID
repo.delete(ucid_string)

# Delete old records
repo.delete_older_than(days=365)
```

---

## Spatial Queries

### Point Queries

```sql
-- UCIDs within radius
SELECT * FROM ucid_scores
WHERE ST_DWithin(
    location::geography,
    ST_SetSRID(ST_MakePoint(28.979, 41.015), 4326)::geography,
    1000  -- meters
);
```

### Bounding Box

```sql
-- UCIDs in bounding box
SELECT * FROM ucid_scores
WHERE location && ST_MakeEnvelope(28.8, 40.9, 29.2, 41.1, 4326);
```

### H3 Queries

```sql
-- Using H3 extension
SELECT * FROM ucid_scores
WHERE h3_index = h3_latlng_to_cell(41.015, 28.979, 9);

-- Neighboring cells
SELECT * FROM ucid_scores
WHERE h3_index = ANY(h3_grid_disk(h3_latlng_to_cell(41.015, 28.979, 9), 1));
```

### Aggregate by Area

```sql
-- Average score by H3 parent cell
SELECT 
    h3_cell_to_parent(h3_index, 7) as parent_cell,
    AVG(score) as avg_score,
    COUNT(*) as cell_count
FROM ucid_scores
WHERE city_code = 'IST' AND context = '15MIN'
GROUP BY parent_cell;
```

---

## Indexing

### Spatial Index

```sql
-- GIST index on geometry
CREATE INDEX idx_ucid_location 
ON ucid_scores USING GIST (location);

-- H3 index
CREATE INDEX idx_ucid_h3 
ON ucid_scores (h3_index);
```

### Composite Indices

```sql
-- City + context + timestamp
CREATE INDEX idx_ucid_city_context_time 
ON ucid_scores (city_code, context, timestamp);

-- City + H3 for spatial queries within city
CREATE INDEX idx_ucid_city_h3 
ON ucid_scores (city_code, h3_index);
```

### Partial Indices

```sql
-- Only high-quality scores
CREATE INDEX idx_ucid_high_quality 
ON ucid_scores (city_code, context)
WHERE grade IN ('A+', 'A');
```

---

## Bulk Operations

### COPY Import

```python
from io import StringIO

def bulk_insert_copy(session, ucids: list[UCID]) -> int:
    """Fast bulk insert using COPY."""
    buffer = StringIO()
    
    for ucid in ucids:
        buffer.write(f"{ucid}\t{ucid.city}\t{ucid.lat}\t{ucid.lon}\t...\n")
    
    buffer.seek(0)
    
    with session.connection().connection.cursor() as cursor:
        cursor.copy_from(
            buffer,
            'ucid_scores',
            columns=['ucid_string', 'city_code', 'lat', 'lon', ...],
        )
    
    return len(ucids)
```

### Batch Processing

```python
def process_city_batch(city: str, batch_size: int = 10000):
    """Process city in batches."""
    offset = 0
    
    while True:
        batch = session.query(UCIDScore)\
            .filter(UCIDScore.city_code == city)\
            .offset(offset)\
            .limit(batch_size)\
            .all()
        
        if not batch:
            break
        
        yield batch
        offset += batch_size
```

---

## Implementation

### UCIDRepository Class

```python
from sqlalchemy.orm import Session
from geoalchemy2.functions import ST_DWithin, ST_SetSRID, ST_MakePoint

class UCIDRepository:
    """Repository for UCID database operations."""
    
    def __init__(self, session: Session):
        self.session = session
    
    def insert(self, ucid: UCID) -> UCIDScore:
        """Insert a single UCID."""
        score = UCIDScore(
            ucid_string=str(ucid),
            city_code=ucid.city,
            h3_index=ucid.h3_index,
            location=f'SRID=4326;POINT({ucid.lon} {ucid.lat})',
            # ... other fields
        )
        self.session.add(score)
        self.session.commit()
        return score
    
    def find_near(
        self,
        lat: float,
        lon: float,
        radius_m: float,
        context: str | None = None,
    ) -> list[UCIDScore]:
        """Find UCIDs within radius of point."""
        query = self.session.query(UCIDScore).filter(
            ST_DWithin(
                UCIDScore.location,
                ST_SetSRID(ST_MakePoint(lon, lat), 4326),
                radius_m,
                use_spheroid=True,
            )
        )
        
        if context:
            query = query.filter(UCIDScore.context == context)
        
        return query.all()
    
    def get_city_summary(self, city: str) -> dict:
        """Get summary statistics for a city."""
        return self.session.execute(
            """
            SELECT 
                context,
                AVG(score) as avg_score,
                COUNT(*) as count,
                MIN(score) as min_score,
                MAX(score) as max_score
            FROM ucid_scores
            WHERE city_code = :city
            GROUP BY context
            """,
            {"city": city},
        ).fetchall()
```

---

## Performance

### Query Performance

| Query Type | Records | Time | With Index |
|------------|---------|------|------------|
| Point (1km radius) | 1M | 50ms | 2ms |
| Bounding box | 1M | 100ms | 5ms |
| H3 exact | 1M | 20ms | <1ms |
| City aggregate | 1M | 500ms | 50ms |

### Optimization Tips

| Technique | Benefit |
|-----------|---------|
| GIST spatial index | 50x faster queries |
| H3 index | Hierarchical queries |
| Partitioning | Parallel scans |
| Connection pooling | Reduced overhead |
| COPY for bulk | 10x faster insert |

---

## Administration

### Maintenance

```sql
-- Vacuum and analyze
VACUUM ANALYZE ucid_scores;

-- Reindex
REINDEX INDEX CONCURRENTLY idx_ucid_location;

-- Check index usage
SELECT indexrelname, idx_scan, idx_tup_read
FROM pg_stat_user_indexes
WHERE schemaname = 'public';
```

### Monitoring

| Metric | Query |
|--------|-------|
| Table size | `pg_size_pretty(pg_total_relation_size('ucid_scores'))` |
| Index size | `pg_size_pretty(pg_indexes_size('ucid_scores'))` |
| Row count | `SELECT reltuples FROM pg_class WHERE relname = 'ucid_scores'` |
| Cache hit | `SELECT heap_blks_hit / heap_blks_read FROM pg_statio_user_tables` |

---

Copyright 2026 UCID Foundation. All rights reserved.

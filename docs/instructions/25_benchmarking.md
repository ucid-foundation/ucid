# Benchmarking

This document provides comprehensive documentation for UCID's performance benchmarking, profiling, and optimization strategies.

---

## Table of Contents

1. [Overview](#overview)
2. [Benchmark Suite](#benchmark-suite)
3. [Performance Metrics](#performance-metrics)
4. [Profiling Tools](#profiling-tools)
5. [Memory Analysis](#memory-analysis)
6. [Optimization Techniques](#optimization-techniques)
7. [Regression Detection](#regression-detection)
8. [CI Integration](#ci-integration)
9. [Benchmark Results](#benchmark-results)
10. [Best Practices](#best-practices)

---

## Overview

UCID includes a comprehensive benchmarking suite to ensure consistent performance across releases and identify optimization opportunities.

### Benchmark Categories

| Category | Operations | Primary Metric | Target |
|----------|------------|----------------|--------|
| Core | UCID creation, parsing | ops/sec | > 500k |
| Spatial | H3 operations, grid generation | ops/sec | > 100k |
| Context | Score computation | ms/location | < 100ms |
| IO | Export, import | MB/sec | > 50 MB/s |
| Network | OSM fetch, API calls | req/sec | > 100 |

### Benchmarking Philosophy

| Principle | Implementation |
|-----------|----------------|
| Reproducibility | Fixed seeds, controlled environment |
| Statistical rigor | Multiple runs, confidence intervals |
| Isolation | Measure one thing at a time |
| Comparison | Track against baselines |
| Automation | CI-integrated benchmarks |

---

## Benchmark Suite

### Running Benchmarks

```bash
# Run all benchmarks
pytest tests/benchmarks/ --benchmark-only

# Run specific benchmark category
pytest tests/benchmarks/test_core.py --benchmark-only

# Run with detailed output
pytest tests/benchmarks/ --benchmark-only --benchmark-verbose

# Save results for comparison
pytest tests/benchmarks/ --benchmark-save=baseline

# Compare with previous results
pytest tests/benchmarks/ --benchmark-compare=baseline

# Generate HTML report
pytest tests/benchmarks/ --benchmark-only --benchmark-autosave \
    --benchmark-histogram=benchmark_histogram
```

### Benchmark Configuration

```python
# conftest.py
import pytest

@pytest.fixture
def benchmark_config():
    return {
        'warmup': True,
        'warmup_iterations': 100,
        'min_rounds': 5,
        'max_time': 5.0,
        'calibration_precision': 10,
    }
```

### Core Benchmarks

```python
import pytest
from ucid import create_ucid, parse_ucid, canonicalize_ucid

class TestCoreBenchmarks:
    """Benchmark core UCID operations."""
    
    @pytest.mark.benchmark(group="core")
    def test_create_ucid_performance(self, benchmark):
        """Benchmark UCID creation."""
        result = benchmark(
            create_ucid,
            city="IST",
            lat=41.015,
            lon=28.979,
            timestamp="2026W01T12",
            context="15MIN",
        )
        assert result is not None
    
    @pytest.mark.benchmark(group="core")
    def test_parse_ucid_performance(self, benchmark):
        """Benchmark UCID parsing."""
        ucid_str = "UCID-V1:IST:+41.015:+028.979:9:891f2ed6df7ffff:2026W01T12:15MIN:A:0.92:"
        result = benchmark(parse_ucid, ucid_str)
        assert result.city == "IST"
    
    @pytest.mark.benchmark(group="core")
    def test_canonicalize_performance(self, benchmark):
        """Benchmark UCID canonicalization."""
        ucid_str = "ucid-v1:IST:+41.015:+28.979:9:891f2ed6df7ffff:2026W01T12:15MIN:A:0.92:"
        result = benchmark(canonicalize_ucid, ucid_str)
        assert result.startswith("UCID-V1:")
    
    @pytest.mark.benchmark(group="core")
    def test_validate_performance(self, benchmark):
        """Benchmark UCID validation."""
        ucid_str = "UCID-V1:IST:+41.015:+028.979:9:891f2ed6df7ffff:2026W01T12:15MIN:A:0.92:"
        result = benchmark(validate_ucid, ucid_str)
        assert result is True
```

### Spatial Benchmarks

```python
import h3

class TestSpatialBenchmarks:
    """Benchmark spatial operations."""
    
    @pytest.mark.benchmark(group="spatial")
    def test_latlng_to_cell(self, benchmark):
        """Benchmark H3 cell lookup."""
        result = benchmark(h3.latlng_to_cell, 41.015, 28.979, 9)
        assert result is not None
    
    @pytest.mark.benchmark(group="spatial")
    def test_k_ring(self, benchmark):
        """Benchmark H3 k-ring generation."""
        cell = h3.latlng_to_cell(41.015, 28.979, 9)
        result = benchmark(h3.grid_disk, cell, 1)
        assert len(result) == 7
    
    @pytest.mark.benchmark(group="spatial")
    def test_grid_generation(self, benchmark):
        """Benchmark H3 grid generation for bbox."""
        bbox = (28.8, 40.9, 29.2, 41.1)
        
        def generate_grid():
            return list(h3.polyfill_geojson(bbox_to_geojson(bbox), 9))
        
        result = benchmark(generate_grid)
        assert len(result) > 0
```

### Context Benchmarks

```python
class TestContextBenchmarks:
    """Benchmark context scoring."""
    
    @pytest.fixture
    def context_15min(self):
        from ucid.contexts import FifteenMinuteContext
        return FifteenMinuteContext()
    
    @pytest.mark.benchmark(group="context")
    def test_15min_cached(self, benchmark, context_15min):
        """Benchmark 15MIN with cache warm."""
        # Warm cache
        context_15min.compute(41.015, 28.979, "2026W01T12")
        
        result = benchmark(
            context_15min.compute,
            41.015, 28.979, "2026W01T12"
        )
        assert result.score >= 0
    
    @pytest.mark.benchmark(group="context")
    def test_15min_cold(self, benchmark, context_15min):
        """Benchmark 15MIN with cold cache."""
        def cold_compute():
            context_15min.cache.clear()
            return context_15min.compute(41.015, 28.979, "2026W01T12")
        
        result = benchmark(cold_compute)
        assert result.score >= 0
```

---

## Performance Metrics

### Core Operations

| Operation | Throughput | Latency (p50) | Latency (p99) | Memory |
|-----------|------------|---------------|---------------|--------|
| create_ucid | 500,000/s | 2 μs | 10 μs | 1 KB |
| parse_ucid | 800,000/s | 1.2 μs | 8 μs | 500 B |
| canonicalize | 1,000,000/s | 1 μs | 5 μs | 200 B |
| validate | 600,000/s | 1.5 μs | 7 μs | 100 B |
| to_string | 2,000,000/s | 0.5 μs | 3 μs | 300 B |

### Spatial Operations

| Operation | Throughput | Notes |
|-----------|------------|-------|
| latlng_to_cell | 1,000,000/s | H3 core operation |
| cell_to_latlng | 1,500,000/s | Reverse lookup |
| grid_disk (k=1) | 500,000/s | 7 cells returned |
| grid_disk (k=2) | 300,000/s | 19 cells returned |
| polyfill (small) | 10,000/s | ~100 cells |
| polyfill (city) | 10/s | ~1M cells |

### Context Scoring

| Context | Latency (cached) | Latency (uncached) | Data Sources |
|---------|------------------|-------------------|--------------|
| 15MIN | 20 ms | 800 ms | OSM |
| TRANSIT | 15 ms | 500 ms | GTFS |
| CLIMATE | 50 ms | 2000 ms | Satellite |
| VITALITY | 25 ms | 600 ms | OSM POI |
| EQUITY | 30 ms | 1000 ms | Census |
| WALK | 20 ms | 400 ms | OSM network |

---

## Profiling Tools

### CPU Profiling

```python
import cProfile
import pstats
from pstats import SortKey

def profile_function(func, *args, **kwargs):
    """Profile a function's CPU usage."""
    profiler = cProfile.Profile()
    profiler.enable()
    
    result = func(*args, **kwargs)
    
    profiler.disable()
    stats = pstats.Stats(profiler)
    stats.sort_stats(SortKey.CUMULATIVE)
    stats.print_stats(20)
    
    return result

# Example usage
profile_function(context.compute, 41.015, 28.979, "2026W01T12")
```

### Line Profiling

```python
from line_profiler import LineProfiler

def line_profile_function(func):
    """Line-by-line profiling."""
    profiler = LineProfiler()
    profiler.add_function(func)
    
    wrapped = profiler(func)
    result = wrapped(41.015, 28.979, "2026W01T12")
    
    profiler.print_stats()
    return result
```

### py-spy Profiling

```bash
# Profile running process
py-spy record -o profile.svg -- python -m ucid.cli score IST 41.015 28.979

# Real-time top
py-spy top --pid <pid>
```

---

## Memory Analysis

### Memory Profiling

```python
from memory_profiler import profile, memory_usage

@profile
def memory_intensive_operation():
    """Profile memory usage."""
    grid = list(generate_grid_h3(istanbul_bbox, resolution=9))
    scores = [compute_score(cell) for cell in grid[:1000]]
    return len(scores)

# Track memory over time
mem_usage = memory_usage(
    (memory_intensive_operation,),
    interval=0.1,
    timeout=60,
)
print(f"Peak memory: {max(mem_usage):.1f} MB")
```

### Object Size Analysis

```python
import sys
from pympler import asizeof

ucid = create_ucid(city="IST", lat=41.015, lon=28.979, ...)

print(f"UCID size (sys): {sys.getsizeof(ucid)} bytes")
print(f"UCID size (deep): {asizeof.asizeof(ucid)} bytes")
```

### Memory Optimization Results

| Object | Before | After | Reduction |
|--------|--------|-------|-----------|
| UCID | 1.2 KB | 500 B | 58% |
| ContextResult | 800 B | 350 B | 56% |
| H3 Grid (1k cells) | 120 KB | 48 KB | 60% |

---

## Optimization Techniques

### Caching

```python
from functools import lru_cache
from cachetools import TTLCache

# LRU cache for pure functions
@lru_cache(maxsize=10000)
def compute_h3_index(lat: float, lon: float, resolution: int) -> str:
    return h3.latlng_to_cell(lat, lon, resolution)

# TTL cache for API responses
osm_cache = TTLCache(maxsize=1000, ttl=3600)

def fetch_with_cache(lat, lon):
    key = f"{lat:.3f},{lon:.3f}"
    if key not in osm_cache:
        osm_cache[key] = fetch_from_osm(lat, lon)
    return osm_cache[key]
```

### Vectorization

```python
import numpy as np

# Slow: Python loop
def calculate_scores_slow(lats, lons):
    return [compute_score(lat, lon) for lat, lon in zip(lats, lons)]

# Fast: Vectorized
def calculate_scores_fast(lats: np.ndarray, lons: np.ndarray):
    vectorized_score = np.vectorize(compute_score)
    return vectorized_score(lats, lons)
```

### Lazy Loading

```python
from importlib import import_module

class LazyContext:
    """Lazy-load context modules."""
    
    _cache = {}
    
    @classmethod
    def get(cls, context_id: str):
        if context_id not in cls._cache:
            module = import_module(f'ucid.contexts.{context_id.lower()}')
            cls._cache[context_id] = module.Context()
        return cls._cache[context_id]
```

---

## Regression Detection

### Automated Detection

```python
def check_performance_regression(current: dict, baseline: dict, threshold: float = 0.1):
    """Detect performance regressions."""
    regressions = []
    
    for operation, current_time in current.items():
        if operation in baseline:
            baseline_time = baseline[operation]
            regression = (current_time - baseline_time) / baseline_time
            
            if regression > threshold:
                regressions.append({
                    'operation': operation,
                    'baseline': baseline_time,
                    'current': current_time,
                    'regression': f"{regression:.1%}",
                })
    
    return regressions
```

---

## CI Integration

### GitHub Actions

```yaml
name: Benchmarks

on:
  push:
    branches: [main]
  pull_request:

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      
      - name: Install dependencies
        run: pip install -e ".[dev]"
      
      - name: Run benchmarks
        run: |
          pytest tests/benchmarks/ \
            --benchmark-only \
            --benchmark-json=benchmark.json
      
      - name: Compare with baseline
        run: |
          python scripts/check_regression.py \
            --baseline benchmarks/baseline.json \
            --current benchmark.json \
            --threshold 0.1
      
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: benchmark-results
          path: benchmark.json
```

---

## Best Practices

### Benchmarking Guidelines

| Guideline | Rationale |
|-----------|-----------|
| Use dedicated machine | Avoid interference |
| Warm up before measuring | Stabilize JIT |
| Run multiple iterations | Statistical significance |
| Control external factors | Network, disk |
| Version control baselines | Track over time |

---

Copyright 2026 UCID Foundation. All rights reserved.

# Roadmap

This document outlines the development roadmap for the UCID (Urban Context Identifier) project, including planned features, milestones, and long-term vision.

---

## Table of Contents

1. [Vision](#vision)
2. [Current Status](#current-status)
3. [Short-Term Goals](#short-term-goals)
4. [Medium-Term Goals](#medium-term-goals)
5. [Long-Term Goals](#long-term-goals)
6. [Release Schedule](#release-schedule)
7. [Feature Backlog](#feature-backlog)
8. [Community Input](#community-input)
9. [Deprecation Schedule](#deprecation-schedule)
10. [Version History](#version-history)

---

## Vision

### Project Vision

UCID aims to become the universal standard for urban context identification and analysis, enabling:

- **Researchers** to conduct reproducible urban studies
- **Planners** to make data-driven decisions
- **Developers** to build urban analytics applications
- **Cities** to benchmark and improve urban quality

### Core Principles

| Principle | Description |
|-----------|-------------|
| **Open Standard** | UCID format is open and vendor-neutral |
| **Extensibility** | Plugin architecture for custom contexts |
| **Reproducibility** | Consistent, reproducible scoring |
| **Accessibility** | Easy to use for all skill levels |
| **Performance** | Scales to city and regional analysis |

### Success Metrics

| Metric | Target (2027) |
|--------|---------------|
| PyPI Downloads | 100,000/month |
| GitHub Stars | 5,000 |
| Scientific Citations | 100 |
| Cities Covered | 500+ |
| Active Contributors | 50+ |

---

## Current Status

### Version 1.0 (Current)

Released: January 2026

#### Features

| Feature | Status |
|---------|--------|
| UCID-V1 format specification | Complete |
| Core parsing and validation | Complete |
| H3 spatial indexing | Complete |
| 6 production contexts | Complete |
| REST API | Complete |
| GeoParquet/GeoJSON export | Complete |
| Docker deployment | Complete |
| Documentation | Complete |

#### Contexts

| Context | Status | Coverage |
|---------|--------|----------|
| 15MIN | Production | Global |
| TRANSIT | Production | GTFS cities |
| CLIMATE | Production | Sentinel-2 coverage |
| VITALITY | Production | OSM coverage |
| EQUITY | Production | Census data countries |
| WALK | Production | OSM coverage |

---

## Short-Term Goals

### Version 1.1 (Q2 2026)

Focus: Stability and performance improvements

#### Planned Features

| Feature | Priority | Status |
|---------|----------|--------|
| Python 3.13 support | High | In Progress |
| S2 cell support | High | In Progress |
| Performance optimization | High | Planned |
| Async API client | Medium | Planned |
| COG raster support | Medium | Planned |
| Enhanced caching | Medium | Planned |

#### Bug Fixes

- Memory optimization for large grids
- Edge cases in timestamp validation
- Thread safety improvements

### Version 1.2 (Q3 2026)

Focus: New contexts and data sources

#### Planned Contexts

| Context | Description | Status |
|---------|-------------|--------|
| SAFETY | Urban safety metrics | Research |
| HEALTH | Health and wellness | Research |
| ECONOMIC | Economic activity | Research |
| MOBILITY | Multi-modal mobility | Planned |

#### Data Integrations

| Source | Data Type | Priority |
|--------|-----------|----------|
| Overture Maps | POIs, Buildings | High |
| Google Open Buildings | Building footprints | Medium |
| Meta Population Data | Population | Medium |
| Air Quality APIs | Environmental | High |

---

## Medium-Term Goals

### Version 2.0 (Q1 2027)

Focus: Major enhancements and breaking changes

#### Planned Changes

| Change | Type | Rationale |
|--------|------|-----------|
| UCID-V2 format | Breaking | Extended metadata support |
| Async-first API | Breaking | Better performance |
| New scoring scale | Breaking | 0-1000 for finer granularity |
| Plugin registry | Feature | Central plugin discovery |

#### New Features

| Feature | Description |
|---------|-------------|
| Federation | Distributed UCID computation |
| Streaming | Real-time score updates |
| ML predictions | AI-powered gap filling |
| Visualization | Built-in mapping |

### Version 2.1 (Q2 2027)

Focus: Enterprise features

#### Enterprise Features

| Feature | Description |
|---------|-------------|
| RBAC | Role-based access control |
| Audit logging | Comprehensive audit trails |
| Multi-tenancy | Shared infrastructure |
| SLA monitoring | Performance guarantees |

---

## Long-Term Goals

### 2028 and Beyond

#### Strategic Initiatives

| Initiative | Timeline | Description |
|------------|----------|-------------|
| Global Coverage | 2028 | All major cities worldwide |
| Real-Time | 2028 | Live context updates |
| AI Integration | 2028 | Predictive analytics |
| Mobile SDK | 2028 | iOS and Android support |
| IoT Integration | 2029 | Sensor data integration |

#### Research Directions

| Area | Focus |
|------|-------|
| Climate Adaptation | Heat resilience scoring |
| Smart Cities | IoT integration |
| Autonomous Vehicles | Navigation contexts |
| Urban AI | ML-enhanced contexts |

---

## Release Schedule

### Release Cadence

| Release Type | Frequency | Content |
|--------------|-----------|---------|
| Major (X.0.0) | 12-18 months | Breaking changes |
| Minor (X.Y.0) | 6-8 weeks | New features |
| Patch (X.Y.Z) | As needed | Bug fixes |

### Upcoming Releases

| Version | Target Date | Focus |
|---------|-------------|-------|
| 1.1.0 | April 2026 | Performance |
| 1.2.0 | August 2026 | New contexts |
| 1.3.0 | December 2026 | Integrations |
| 2.0.0 | March 2027 | Major update |

---

## Feature Backlog

### High Priority

| Feature | Votes | Complexity |
|---------|-------|------------|
| S2 cell support | 45 | Medium |
| Async client | 38 | Low |
| SAFETY context | 35 | High |
| Overture integration | 32 | Medium |
| Real-time updates | 28 | High |

### Medium Priority

| Feature | Votes | Complexity |
|---------|-------|------------|
| HEALTH context | 25 | High |
| GraphQL API | 22 | Medium |
| Jupyter widgets | 20 | Low |
| PDF reports | 18 | Low |
| Time machine | 15 | High |

### Low Priority

| Feature | Votes | Complexity |
|---------|-------|------------|
| Mobile SDK | 12 | High |
| Desktop app | 10 | High |
| Voice commands | 5 | Medium |

---

## Community Input

### How to Influence the Roadmap

1. **Vote on Issues**: Use reactions on GitHub issues
2. **Propose Features**: Open feature request discussions
3. **Join Discussions**: Participate in roadmap planning
4. **Sponsor Development**: Fund specific features

### Roadmap Meetings

| Meeting | Frequency | Participants |
|---------|-----------|--------------|
| TSC Roadmap Review | Monthly | TSC members |
| Community Roadmap Call | Quarterly | Open |

### Feedback Channels

- GitHub Discussions: Feature requests
- Discord: Real-time feedback
- Mailing List: Announcements
- X: Updates

---

## Deprecation Schedule

### Planned Deprecations

| Feature | Deprecated | Removed | Migration |
|---------|------------|---------|-----------|
| `h3_resolution` parameter | v1.1 | v2.0 | Use `resolution` |
| `ucid.core.parser` imports | v1.0 | v2.0 | Use `ucid` root |
| Legacy city codes | v1.2 | v2.0 | Use UN/LOCODE |

### Deprecation Policy

| Phase | Timeline | Action |
|-------|----------|--------|
| Announcement | Version N | Warning in changelog |
| Warning | Version N+1 | Runtime deprecation warning |
| Removal | Version N+2 | Feature removed |

---

## Version History

### Roadmap Updates

| Date | Changes |
|------|---------|
| 2026-01-01 | Initial roadmap |

---

## Contributing to the Roadmap

### Proposing Features

1. Check existing proposals
2. Open a feature request
3. Gather community feedback
4. TSC review

### Sponsoring Development

Contact: sponsors@ucid.org

---

## Disclaimer

This roadmap represents current plans and is subject to change. Features may be added, removed, or reprioritized based on community feedback, technical constraints, and resource availability.

---

## Technical Dependencies

### Python Ecosystem

| Package | Current | Target (2.0) |
|---------|---------|--------------|
| Python | 3.11+ | 3.12+ |
| h3 | 4.x | 4.x |
| pandas | 2.x | 2.x |
| geopandas | 0.14+ | 1.0+ |
| pydantic | 2.x | 2.x |

### External Systems

| System | Integration Status |
|--------|-------------------|
| OpenStreetMap | Production |
| GTFS/GTFS-RT | Production |
| Sentinel-2 | Production |
| Overture Maps | Planned |
| Google Building | Planned |

---

## Risk Assessment

### Technical Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| H3 API changes | High | Compatibility layer |
| Data source unavailability | Medium | Multiple sources |
| Performance regression | Medium | Continuous benchmarking |
| Security vulnerabilities | High | Regular auditing |

### Project Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Contributor burnout | High | Sustainable pace |
| Scope creep | Medium | Clear governance |
| Competition | Low | Open standards |
| Funding | Medium | Diversified sponsors |

---

## Success Criteria

### Version 1.x Success

| Criterion | Target | Metric |
|-----------|--------|--------|
| Adoption | 10,000 users | PyPI downloads |
| Quality | 95% uptime | Monitoring |
| Performance | 1000 UCIDs/sec | Benchmarks |
| Documentation | 90% coverage | Doc coverage |

### Version 2.0 Success

| Criterion | Target | Metric |
|-----------|--------|--------|
| Migration | 80% of v1 users | Telemetry |
| New features | SAFETY context | Release notes |
| Performance | 2x improvement | Benchmarks |

---

## Related Projects

### Complementary Projects

| Project | Relationship |
|---------|--------------|
| OSMnx | Data source |
| Kepler.gl | Visualization |
| H3-py | Spatial indexing |
| GTFS-kit | Transit data |

### Competing Approaches

| Approach | Differentiation |
|----------|-----------------|
| Walk Score | UCID is open source, multi-context |
| Location Intelligence | UCID is standardized, reproducible |
| Custom indices | UCID is transferable, shareable |

---

Copyright 2026 UCID Foundation. All rights reserved.

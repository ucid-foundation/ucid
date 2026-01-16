# UCID Support

## Document Information

| Field | Value |
|-------|-------|
| Document Title | UCID Support and Help Guide |
| Version | 1.0.5 |
| Last Updated | 2026-01-16 |
| Maintainer | UCID Foundation |
| Contact | support@ucid.org |

---

## Table of Contents

1. [Getting Help](#getting-help)
2. [Documentation](#documentation)
3. [Community Resources](#community-resources)
4. [Issue Reporting](#issue-reporting)
5. [Frequently Asked Questions](#frequently-asked-questions)
6. [Troubleshooting](#troubleshooting)
7. [Professional Support](#professional-support)
8. [Training Resources](#training-resources)
9. [Feedback](#feedback)

---

## Library Statistics

| Metric | Value |
|--------|-------|
| Total Cities | 405 |
| Countries | 23 |
| CREATE Performance | 127,575 ops/sec |
| PARSE Performance | 61,443 ops/sec |
| Test Coverage | 85%+ |

---

## Getting Help

### Support Channels Overview

| Channel | Best For | Response Time |
|---------|----------|---------------|
| Documentation | Self-service learning | Immediate |
| GitHub Discussions | General questions | 1-3 days |
| GitHub Issues | Bug reports | 1-7 days |
| Stack Overflow | Technical questions | Community |
| Discord | Real-time chat | Community |
| Email | Private inquiries | 3-5 days |

### Choosing the Right Channel

```mermaid
flowchart TD
    A[Need Help] --> B{What kind?}
    B -->|Bug| C[GitHub Issues]
    B -->|Question| D[Discussions]
    B -->|Security| E[security@ucid.org]
    B -->|Feature| F[GitHub Issues]
    B -->|General| G[Discord]
    B -->|Private| H[Email]
```

---

## Documentation

### Official Documentation

| Resource | URL | Description |
|----------|-----|-------------|
| README | GitHub README | Quick start guide |
| API Docs | docs.ucid.org | API reference |
| User Guide | docs.ucid.org/guide | Complete user guide |
| Examples | examples/ | Code examples |

### Documentation Structure

```
docs/
├── instructions/           # Step-by-step guides
│   ├── 00_project_overview.md
│   ├── 01_installation.md
│   ├── 02_quickstart.md
│   └── ...
├── api/                    # API reference
└── examples/               # Usage examples
```

### In-Code Documentation

All public functions have docstrings:

```python
from ucid import create_ucid

help(create_ucid)  # View documentation
```

---

## Community Resources

### GitHub

| Resource | URL | Purpose |
|----------|-----|---------|
| Repository | github.com/ucid-foundation/ucid | Source code |
| Issues | /issues | Bug reports, features |
| Discussions | /discussions | Q&A, ideas |
| Wiki | /wiki | Community docs |

### Social Media

| Platform | Handle | Purpose |
|----------|--------|---------|
| Twitter/X | @ucid_org | Announcements |
| LinkedIn | UCID Foundation | Professional updates |
| YouTube | UCID Foundation | Tutorials |

### Community Chat

| Platform | Link | Purpose |
|----------|------|---------|
| Discord | discord.gg/ucid | Real-time help |

---

## Issue Reporting

### Before Creating an Issue

1. **Search existing issues** - Your issue may already be reported
2. **Check documentation** - The answer may be in the docs
3. **Try latest version** - Update to see if issue persists
4. **Minimal reproduction** - Create a minimal example

### Bug Report Template

```markdown
## Bug Description
[Clear, concise description]

## Environment
- Python version: `python --version`
- UCID version: `pip show ucid`
- Operating System:

## Steps to Reproduce
1. Step 1
2. Step 2
3. Step 3

## Expected Behavior
[What should happen]

## Actual Behavior
[What actually happens]

## Error Message
```
[Full error traceback]
```

## Minimal Reproduction
```python
# Minimal code that reproduces the issue
from ucid import create_ucid

# Your code here
```

## Additional Context
[Screenshots, logs, etc.]
```

### Feature Request Template

```markdown
## Feature Description
[Clear description of the feature]

## Use Case
[Why is this feature needed?]

## Proposed Solution
[How might this work?]

## Alternatives Considered
[Other approaches you considered]

## Additional Context
[Mockups, examples, etc.]
```

---

## Frequently Asked Questions

### Installation

**Q: How do I install UCID?**

```bash
pip install ucid
```

**Q: What Python versions are supported?**

A: Python 3.11, 3.12, and 3.13.

**Q: How do I install optional dependencies?**

```bash
pip install "ucid[all]"      # All features
pip install "ucid[contexts]"  # Context algorithms
pip install "ucid[api]"       # REST API
```

### Basic Usage

**Q: How do I create a UCID?**

```python
from ucid import create_ucid

ucid = create_ucid(
    city="IST",
    lat=41.015,
    lon=28.979,
    timestamp="2026W03T14",
    context="15MIN",
)
print(ucid)
```

**Q: How do I parse a UCID string?**

```python
from ucid import parse_ucid

ucid = parse_ucid("UCID-V1:IST:+41.015:+28.979:9:...")
print(f"City: {ucid.city}, Grade: {ucid.grade}")
```

**Q: What cities are supported?**

A: 405 cities across 23 countries. List them with:

```python
from ucid import list_cities

for city in list_cities():
    print(f"{city.code}: {city.name}, {city.country}")
```

### Contexts

**Q: What contexts are available?**

| Context | Description |
|---------|-------------|
| 15MIN | 15-Minute City accessibility |
| TRANSIT | Public transit quality |
| WALK | Walkability score |
| NONE | No context scoring |

**Q: How do I use contexts?**

```python
from ucid import create_ucid

# With 15MIN context
ucid = create_ucid(
    city="IST",
    lat=41.015,
    lon=28.979,
    context="15MIN",
)
print(f"Grade: {ucid.grade}, Confidence: {ucid.confidence}")
```

### Performance

**Q: What is the performance?**

| Operation | Performance |
|-----------|-------------|
| CREATE | 127,575 ops/sec |
| PARSE | 61,443 ops/sec |
| VALIDATE | 17,334 ops/sec |

**Q: How can I improve performance?**

1. Use batch processing for multiple UCIDs
2. Enable caching for context scoring
3. Use appropriate H3 resolution

### API

**Q: Is there a REST API?**

A: Yes. Install with:

```bash
pip install "ucid[api]"
```

Run with:

```bash
uvicorn ucid.api:app --host 0.0.0.0 --port 8000
```

---

## Troubleshooting

### Common Issues

#### Installation Errors

**Issue**: `ModuleNotFoundError: No module named 'h3'`

**Solution**:
```bash
pip install h3
```

**Issue**: Installation fails on Windows

**Solution**:
```bash
pip install --upgrade pip
pip install ucid
```

#### Runtime Errors

**Issue**: `UCIDParseError: Invalid UCID format`

**Solution**: Ensure UCID string follows correct format:
```
UCID-V1:{CITY}:{LAT}:{LON}:{RES}:{H3}:{TIME}:{CTX}:{GRADE}:{CONF}
```

**Issue**: `UCIDValidationError: Invalid city code`

**Solution**: Use valid 3-letter city codes:
```python
from ucid import list_cities
print([c.code for c in list_cities()])
```

#### Performance Issues

**Issue**: Slow context scoring

**Solution**: Enable caching:
```python
from ucid.contexts import FifteenMinContext

context = FifteenMinContext(cache_enabled=True)
```

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

## Professional Support

### Enterprise Support

For enterprise users requiring dedicated support:

| Tier | Features | Contact |
|------|----------|---------|
| Standard | Email support, 48h response | enterprise@ucid.org |
| Premium | Priority support, 24h response | enterprise@ucid.org |
| Enterprise | Dedicated support, SLA | enterprise@ucid.org |

### Consulting Services

Available consulting services:

| Service | Description |
|---------|-------------|
| Integration | Help integrating UCID |
| Custom Contexts | Develop custom contexts |
| Training | On-site or remote training |
| Optimization | Performance optimization |

---

## Training Resources

### Tutorials

| Tutorial | Level | Duration |
|----------|-------|----------|
| Getting Started | Beginner | 30 min |
| Context Algorithms | Intermediate | 1 hour |
| API Integration | Intermediate | 1 hour |
| Performance Tuning | Advanced | 2 hours |

### Examples

Find examples in the `examples/` directory:

```
examples/
├── basic_usage.py
├── batch_processing.py
├── context_scoring.py
├── api_client.py
└── visualization.py
```

### Workshops

| Workshop | Frequency | Format |
|----------|-----------|--------|
| UCID Introduction | Monthly | Online |
| Advanced UCID | Quarterly | Online |
| Conference Sessions | Annual | In-person |

---

## Feedback

### Providing Feedback

We welcome feedback on:

- Documentation quality
- API usability
- Feature requests
- General experience

### Feedback Channels

| Type | Channel |
|------|---------|
| General | feedback@ucid.org |
| Documentation | GitHub issues |
| Features | GitHub discussions |
| Surveys | Periodic email surveys |

### User Research

Participate in user research:

1. User interviews
2. Usability testing
3. Beta testing

Contact: research@ucid.org

---

## Contact Summary

| Purpose | Contact |
|---------|---------|
| General Support | support@ucid.org |
| Security Issues | security@ucid.org |
| Enterprise | enterprise@ucid.org |
| Feedback | feedback@ucid.org |
| Research | research@ucid.org |

---

## Release Information

### Current Version

| Version | Date | Notes |
|---------|------|-------|
| 1.0.5 | 2026-01-16 | Latest stable |

### Getting Updates

```bash
# Upgrade to latest
pip install --upgrade ucid

# Check current version
python -c "import ucid; print(ucid.__version__)"
```

---

## References

- [UCID Documentation](https://docs.ucid.org)
- [GitHub Repository](https://github.com/ucid-foundation/ucid)
- [API Reference](https://docs.ucid.org/api)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- [PyPI Package](https://pypi.org/project/ucid/)

---

Copyright 2026 UCID Foundation. All rights reserved.
Licensed under EUPL-1.2.

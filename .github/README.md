# GitHub Configuration Directory

## Document Information

| Field | Value |
|-------|-------|
| Directory | .github |
| Purpose | GitHub-specific configuration |
| Last Updated | 2026-01-16 |
| Maintainer | UCID Foundation |

---

## Overview

This directory contains GitHub-specific configuration files for the UCID repository. These files control GitHub Actions workflows, issue templates, pull request templates, code ownership, security policies, and other GitHub features.

---

## Directory Structure

```
.github/
├── ISSUE_TEMPLATE/           # Issue templates
│   ├── bug_report.yml        # Bug report template
│   ├── feature_request.yml   # Feature request template
│   ├── documentation.yml     # Documentation issue template
│   └── config.yml            # Template configuration
├── workflows/                # GitHub Actions workflows
│   ├── ci.yml               # Continuous integration
│   ├── release.yml          # Release automation
│   ├── docs.yml             # Documentation build
│   ├── scorecard.yml        # OpenSSF Scorecard
│   ├── codeql.yml           # CodeQL security analysis
│   ├── dependency-review.yml # Dependency review
│   └── stale.yml            # Stale issue management
├── CODEOWNERS               # Code ownership definitions
├── CONTRIBUTING.md          # Contribution guidelines
├── FUNDING.yml              # Sponsorship configuration
├── PULL_REQUEST_TEMPLATE.md # PR template
├── SECURITY.md              # Security policy
├── dependabot.yml           # Dependabot configuration
└── README.md                # This file
```

---

## Workflows

### Continuous Integration (ci.yml)

The CI workflow runs on every push and pull request:

| Job | Description | Runs On |
|-----|-------------|---------|
| lint | Code linting with Ruff | ubuntu-latest |
| type-check | Type checking with mypy | ubuntu-latest |
| test | Unit tests with pytest | ubuntu-latest, windows-latest, macos-latest |
| coverage | Code coverage reporting | ubuntu-latest |
| build | Package build verification | ubuntu-latest |

### Release Workflow (release.yml)

Automated release process:

| Step | Description |
|------|-------------|
| Version bump | Update version in pyproject.toml |
| Changelog | Generate changelog from commits |
| Build | Build wheel and sdist |
| Publish | Publish to PyPI |
| GitHub Release | Create GitHub release |
| SBOM | Generate software bill of materials |

### Security Workflows

| Workflow | Purpose |
|----------|---------|
| codeql.yml | Static code analysis for security |
| scorecard.yml | OpenSSF Scorecard assessment |
| dependency-review.yml | Dependency vulnerability check |

---

## Issue Templates

### Bug Report

For reporting bugs and defects in the library.

Required fields:
- Description
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment (Python version, OS, UCID version)

### Feature Request

For proposing new features or enhancements.

Required fields:
- Description
- Use case
- Proposed solution
- Alternatives considered

### Documentation

For documentation improvements or corrections.

Required fields:
- Description
- Current documentation
- Suggested improvement

---

## Code Owners

The CODEOWNERS file defines who is responsible for reviewing changes to specific parts of the codebase:

| Path | Owner |
|------|-------|
| * | @ucid-foundation/core |
| /src/ucid/core/ | @ucid-foundation/core |
| /src/ucid/contexts/ | @ucid-foundation/contexts |
| /src/ucid/api/ | @ucid-foundation/api |
| /docs/ | @ucid-foundation/docs |
| /.github/ | @ucid-foundation/devops |

---

## Dependabot Configuration

Dependabot is configured to automatically update dependencies:

| Ecosystem | Schedule | Directory |
|-----------|----------|-----------|
| pip | weekly | / |
| github-actions | weekly | /.github/workflows |

---

## Branch Protection

The main branch has the following protection rules:

| Rule | Setting |
|------|---------|
| Require pull request reviews | 1 |
| Require status checks | ci, type-check, lint |
| Require signed commits | Yes |
| Include administrators | Yes |

---

## Labels

Standard labels for issues and pull requests:

| Label | Description | Color |
|-------|-------------|-------|
| bug | Something is not working | #d73a4a |
| enhancement | New feature or request | #a2eeef |
| documentation | Documentation improvements | #0075ca |
| good first issue | Good for newcomers | #7057ff |
| help wanted | Extra attention needed | #008672 |
| priority: high | High priority issue | #b60205 |
| priority: medium | Medium priority issue | #fbca04 |
| priority: low | Low priority issue | #0e8a16 |

---

## Secrets and Variables

Required repository secrets:

| Secret | Purpose |
|--------|---------|
| PYPI_API_TOKEN | PyPI publishing |
| CODECOV_TOKEN | Coverage reporting |
| GITHUB_TOKEN | GitHub API (automatic) |

---

## References

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [GitHub Issue Templates](https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests)
- [CODEOWNERS Documentation](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
- [Dependabot Documentation](https://docs.github.com/en/code-security/dependabot)

---

Copyright 2026 UCID Foundation. All rights reserved.
Licensed under EUPL-1.2.

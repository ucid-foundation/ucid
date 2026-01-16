# ==============================================================================
# UCID Makefile
# Urban Context Identifier - Python Library
# Version: 1.0.5
# Copyright 2026 UCID Foundation. Licensed under EUPL-1.2.
# ==============================================================================
#
# Usage:
#   make help          - Show all available commands
#   make install       - Install development dependencies
#   make test          - Run test suite
#   make lint          - Run linters
#   make build         - Build distribution packages
#
# ==============================================================================

.PHONY: all help install install-dev install-all test test-unit test-integration \
        test-cov lint format type-check security audit clean docs docs-serve \
        build publish publish-test docker-build docker-run pre-commit update-deps \
        benchmark profile

# ==============================================================================
# Variables
# ==============================================================================
PYTHON := python
PIP := pip
PYTEST := pytest
RUFF := ruff
MYPY := mypy
DOCKER := docker
DOCKER_COMPOSE := docker-compose

PROJECT_NAME := ucid
SRC_DIR := src/ucid
TEST_DIR := tests
DOCS_DIR := docs

# Docker settings
DOCKER_IMAGE := ucid/ucid-api
DOCKER_TAG := latest

# ==============================================================================
# Default Target
# ==============================================================================
all: help

# ==============================================================================
# Help
# ==============================================================================
help:
	@echo ""
	@echo "UCID Development Commands"
	@echo "========================="
	@echo ""
	@echo "Installation:"
	@echo "  install        Install with dev dependencies"
	@echo "  install-dev    Install with all dev tools"
	@echo "  install-all    Install with all optional dependencies"
	@echo ""
	@echo "Testing:"
	@echo "  test           Run all tests"
	@echo "  test-unit      Run unit tests only"
	@echo "  test-integration  Run integration tests"
	@echo "  test-cov       Run tests with coverage report"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint           Run linter (ruff)"
	@echo "  format         Format code (ruff)"
	@echo "  type-check     Run type checker (mypy)"
	@echo "  security       Run security checks (bandit)"
	@echo "  audit          Run dependency audit"
	@echo "  pre-commit     Run all pre-commit hooks"
	@echo ""
	@echo "Documentation:"
	@echo "  docs           Build documentation"
	@echo "  docs-serve     Serve documentation locally"
	@echo ""
	@echo "Build & Publish:"
	@echo "  build          Build distribution packages"
	@echo "  publish        Publish to PyPI"
	@echo "  publish-test   Publish to TestPyPI"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build   Build Docker image"
	@echo "  docker-run     Run Docker container"
	@echo ""
	@echo "Utilities:"
	@echo "  clean          Clean build artifacts"
	@echo "  update-deps    Update dependencies"
	@echo "  benchmark      Run performance benchmarks"
	@echo "  profile        Profile code performance"
	@echo ""

# ==============================================================================
# Installation
# ==============================================================================
install:
	$(PIP) install -e ".[dev]"
	pre-commit install

install-dev:
	$(PIP) install -e ".[dev,test,lint,security]"
	pre-commit install

install-all:
	$(PIP) install -e ".[all,dev,test,lint,security,docs]"
	pre-commit install

# ==============================================================================
# Testing
# ==============================================================================
test:
	$(PYTEST) $(TEST_DIR)/ -v

test-unit:
	$(PYTEST) $(TEST_DIR)/unit/ -v

test-integration:
	$(PYTEST) $(TEST_DIR)/integration/ -v -m integration

test-performance:
	$(PYTEST) $(TEST_DIR)/performance/ -v -m performance

test-cov:
	$(PYTEST) $(TEST_DIR)/ -v \
		--cov=$(SRC_DIR) \
		--cov-report=html \
		--cov-report=xml \
		--cov-report=term-missing \
		--cov-fail-under=80
	@echo ""
	@echo "Coverage report: htmlcov/index.html"

test-quick:
	$(PYTEST) $(TEST_DIR)/unit/ -v -x --tb=short

# ==============================================================================
# Code Quality
# ==============================================================================
lint:
	$(RUFF) check $(SRC_DIR) $(TEST_DIR) examples scripts

format:
	$(RUFF) format $(SRC_DIR) $(TEST_DIR) examples scripts
	$(RUFF) check --fix $(SRC_DIR) $(TEST_DIR) examples scripts

type-check:
	$(MYPY) $(SRC_DIR) --ignore-missing-imports

security:
	bandit -r $(SRC_DIR) -ll -c pyproject.toml

audit:
	pip-audit --strict --desc on

pre-commit:
	pre-commit run --all-files

# ==============================================================================
# Cleaning
# ==============================================================================
clean:
	rm -rf dist/ build/ *.egg-info .eggs/
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/
	rm -rf htmlcov/ .coverage coverage.xml
	rm -rf .tox/ .nox/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type f -name "*.egg" -delete 2>/dev/null || true
	@echo "Cleaned build artifacts"

clean-all: clean
	rm -rf .venv venv env
	@echo "Cleaned virtual environments"

# ==============================================================================
# Documentation
# ==============================================================================
docs:
	cd $(DOCS_DIR) && make html
	@echo ""
	@echo "Documentation: $(DOCS_DIR)/_build/html/index.html"

docs-serve:
	cd $(DOCS_DIR)/_build/html && $(PYTHON) -m http.server 8080

docs-clean:
	cd $(DOCS_DIR) && make clean

# ==============================================================================
# Build & Publish
# ==============================================================================
build: clean
	$(PYTHON) -m build

publish: build
	$(PYTHON) -m twine upload dist/*

publish-test: build
	$(PYTHON) -m twine upload --repository testpypi dist/*

# ==============================================================================
# Docker
# ==============================================================================
docker-build:
	$(DOCKER) build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

docker-run:
	$(DOCKER) run -p 8000:8000 $(DOCKER_IMAGE):$(DOCKER_TAG)

docker-compose-up:
	$(DOCKER_COMPOSE) up -d

docker-compose-down:
	$(DOCKER_COMPOSE) down

docker-compose-logs:
	$(DOCKER_COMPOSE) logs -f

# ==============================================================================
# Development Utilities
# ==============================================================================
update-deps:
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) install -e ".[dev]" --upgrade

benchmark:
	$(PYTHON) scripts/benchmark.py --iterations 10000

profile:
	$(PYTHON) -m cProfile -o profile.stats scripts/benchmark.py
	$(PYTHON) -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative').print_stats(30)"

# ==============================================================================
# CI/CD Helpers
# ==============================================================================
ci-install:
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev,test]"

ci-test:
	$(PYTEST) $(TEST_DIR)/ -v --tb=short --junitxml=test-results.xml

ci-lint:
	$(RUFF) check $(SRC_DIR) $(TEST_DIR) --output-format=github

# ==============================================================================
# End of Makefile
# ==============================================================================

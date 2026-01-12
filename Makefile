.PHONY: install install-all test test-cov lint format type-check security clean docs build publish help

# Default target
help:
	@echo "UCID Development Commands"
	@echo "========================="
	@echo "install      - Install with dev dependencies"
	@echo "install-all  - Install with all optional dependencies"
	@echo "test         - Run tests"
	@echo "test-cov     - Run tests with coverage"
	@echo "lint         - Run linter (ruff)"
	@echo "format       - Format code (ruff)"
	@echo "type-check   - Run type checker (mypy)"
	@echo "security     - Run security checks"
	@echo "clean        - Clean build artifacts"
	@echo "docs         - Build documentation"
	@echo "build        - Build distribution packages"
	@echo "publish      - Publish to PyPI (requires API token)"

# Installation
install:
	pip install -e ".[dev]"
	pre-commit install

install-all:
	pip install -e ".[all,dev,docs,security]"
	pre-commit install

# Testing
test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=ucid --cov-report=html --cov-report=xml
	@echo "Coverage report: htmlcov/index.html"

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v -m integration

# Code Quality
lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

type-check:
	mypy src/ucid

security:
	bandit -r src/ucid -ll
	pip-audit --strict

# Cleaning
clean:
	rm -rf dist/ build/ *.egg-info .eggs/
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/
	rm -rf htmlcov/ .coverage coverage.xml
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

# Documentation
docs:
	cd docs && make html
	@echo "Documentation: docs/_build/html/index.html"

docs-serve:
	cd docs && python -m http.server 8080 --directory _build/html

# Build & Publish
build: clean
	python -m build

publish: build
	python -m twine upload dist/*

publish-test: build
	python -m twine upload --repository testpypi dist/*

# Development helpers
pre-commit:
	pre-commit run --all-files

update-deps:
	pip install --upgrade pip setuptools wheel
	pip install -e ".[dev]" --upgrade

# Docker
docker-build:
	docker build -t ucid:latest .

docker-run:
	docker run -p 8000:8000 ucid:latest

# Makefile for Pyrate vulnerability scanner

.PHONY: help install install-dev test lint format clean build docker run

# Default target
help:
	@echo "Available targets:"
	@echo "  install      Install the package"
	@echo "  install-dev  Install development dependencies"
	@echo "  test         Run tests"
	@echo "  lint         Run linting checks"
	@echo "  format       Format code"
	@echo "  clean        Clean build artifacts"
	@echo "  build        Build the package"
	@echo "  docker       Build Docker image"
	@echo "  run          Run the scanner with sample config"

# Installation targets
install:
	uv pip install -e .

install-dev:
	uv pip install -e ".[dev,test,docs]"
	pre-commit install

# Testing targets
test:
	pytest tests/ -v --cov=pyrate --cov-report=html --cov-report=term-missing

test-quick:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

# Code quality targets
lint:
	flake8 src/ tests/
	mypy src/
	bandit -r src/

format:
	black src/ tests/
	isort src/ tests/

format-check:
	black --check src/ tests/
	isort --check-only src/ tests/

# Security checks
security:
	bandit -r src/
	safety check

# Build targets
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	python -m build

# Docker targets
docker:
	docker build -t pyrate:latest .

docker-run:
	docker run -it --rm \
		-v $(PWD)/reports:/app/reports \
		-v $(PWD)/logs:/app/logs \
		pyrate:latest

# Development targets
dev-setup: install-dev
	mkdir -p logs reports config plugins
	pyrate init-config -o config/pyrate-config.yaml
	cp .env.example .env

run:
	pyrate --help

scan-example:
	pyrate scan https://httpbin.org -o reports/example-scan.json

# Documentation targets
docs-build:
	mkdocs build

docs-serve:
	mkdocs serve

# Git hooks
pre-commit:
	pre-commit run --all-files

# Environment management
env-check:
	@echo "Python version: $$(python --version)"
	@echo "UV version: $$(uv --version)"
	@echo "Virtual environment: $${VIRTUAL_ENV:-Not in virtual environment}"

# Package information
version:
	@python -c "from pyrate import __version__; print(__version__)"

info:
	@echo "Pyrate - Web Application Vulnerability Scanner"
	@echo "Version: $$(python -c 'from pyrate import __version__; print(__version__)')"
	@echo "Python: $$(python --version)"
	@echo "UV: $$(uv --version)"
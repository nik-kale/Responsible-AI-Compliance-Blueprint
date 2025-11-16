.PHONY: help install test lint format clean init run ui docker

help:  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install the package in development mode
	pip install -e ".[dev]"

install-pdf:  ## Install with PDF support
	pip install -e ".[all]"

test:  ## Run tests with coverage
	pytest --cov=raicb --cov-report=html --cov-report=term

test-fast:  ## Run tests without coverage
	pytest -x

lint:  ## Run linters
	ruff check src/ tests/
	black --check src/ tests/

format:  ## Format code with black
	black src/ tests/ app/
	ruff check --fix src/ tests/

type-check:  ## Run type checking
	mypy src/

clean:  ## Clean build artifacts and caches
	rm -rf build/ dist/ *.egg-info htmlcov/ .coverage .pytest_cache/ .mypy_cache/ .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

init:  ## Initialize a sample project in current directory
	raicb init

validate:  ## Validate raicb.yaml in current directory
	raicb validate

run:  ## Run compliance check on current directory
	raicb run --verbose

ui:  ## Launch Streamlit UI
	streamlit run app/streamlit_app.py

sbom:  ## Generate SBOM
	raicb sbom

docker-build:  ## Build Docker image
	docker build -t raicb:latest -f docker/Dockerfile .

docker-run-cli:  ## Run Docker container in CLI mode
	docker run --rm -v $(PWD):/workspace raicb:latest --help

docker-run-ui:  ## Run Docker container in UI mode
	docker run --rm -e MODE=ui -p 8501:8501 raicb:latest

pre-commit:  ## Install pre-commit hooks
	pre-commit install

bump-version:  ## Bump version (usage: make bump-version VERSION=0.2.0)
	@if [ -z "$(VERSION)" ]; then echo "Usage: make bump-version VERSION=0.2.0"; exit 1; fi
	sed -i 's/__version__ = ".*"/__version__ = "$(VERSION)"/' src/raicb/__init__.py
	sed -i 's/version = ".*"/version = "$(VERSION)"/' pyproject.toml
	@echo "Version bumped to $(VERSION)"

publish-test:  ## Publish to Test PyPI
	python -m build
	twine upload --repository testpypi dist/*

publish:  ## Publish to PyPI
	python -m build
	twine upload dist/*

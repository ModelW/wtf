.PHONY: help clean format lint typecheck test prettier eval

PYTHON_BIN ?= uv run python

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

clean: prettier format lint ## Format then lint (leaves the tree ready to commit)

prettier: ## Format Markdown/YAML with prettier
	pnpx prettier -w "**/*.{md,yml,yaml}"

format: ## Format all Python code (ruff: import sorting + formatting)
	$(PYTHON_BIN) -m ruff check --fix --select I .
	$(PYTHON_BIN) -m ruff format .

lint: typecheck ## Lint (ruff) and type-check all Python code
	$(PYTHON_BIN) -m ruff check .
	$(PYTHON_BIN) -m ruff format --check .

typecheck: ## Type-check with mypy
	$(PYTHON_BIN) -m mypy

test: ## Run the test suite
	uv run pytest

eval: ## Run the agent eval fixtures against a real model (needs OPENROUTER_API_KEY)
	uv run model-wtf compliance eval --template tests/eval/template --variants tests/eval/variants

.PHONY: sync lint format type test check

sync: ## Install/refresh the workspace environment
	uv sync

lint: ## Ruff lint + formatting check
	uv run ruff check .
	uv run ruff format --check .

format: ## Auto-fix lint findings and reformat
	uv run ruff check --fix .
	uv run ruff format .

type: ## mypy across apps/ and packages/
	uv run mypy

test: ## pytest across all workspace members
	uv run pytest

check: lint type test ## Everything CI runs

.PHONY: sync lint format type test check images images-verify

IMAGE_TAG ?= local
API_IMAGE ?= icebergsst/api:$(IMAGE_TAG)
ENGINE_IMAGE ?= icebergsst/engine:$(IMAGE_TAG)

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

images: ## Build the api and engine role images
	docker build -f deploy/docker/api.Dockerfile -t $(API_IMAGE) .
	docker build -f deploy/docker/engine.Dockerfile -t $(ENGINE_IMAGE) .

images-verify: images ## Build the images, then assert their acceptance criteria
	API_IMAGE=$(API_IMAGE) ENGINE_IMAGE=$(ENGINE_IMAGE) deploy/docker/verify-images.sh

check: lint type test ## Everything CI runs

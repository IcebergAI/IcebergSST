COMPOSE ?= docker compose -f deploy/compose/docker-compose.yml --env-file .env
# Engine replica count for `make scale`.
N ?= 2

.PHONY: help sync hooks lint format type test check images images-verify \
        helm-verify helm-template up down destroy \
        migrate seed logs ps scale init-env secrets

help: ## List the available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

# ─── Workspace ────────────────────────────────────────────────────────────────

sync: ## Install/refresh the workspace environment (and install git hooks)
	uv sync
	$(MAKE) hooks

# Hooks are per-clone: .pre-commit-config.yaml is committed, .git/hooks is not.
# Without this the gitleaks hook — the one that stops a secret reaching history in
# the first place — is silently absent from every fresh clone. CI runs the same
# checks either way, but by then the secret is already committed.
hooks: ## Install the pre-commit hooks into this clone
	uv run pre-commit install --install-hooks

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

# ─── Images ───────────────────────────────────────────────────────────────────

images: ## Build both role images
	docker build -f deploy/docker/api.Dockerfile -t icebergsst/api:verify .
	docker build -f deploy/docker/engine.Dockerfile -t icebergsst/engine:verify .

# Properties of the built artefact rather than of the Dockerfile text: both
# entrypoints serve, both run non-root, and no database package is importable in
# the engine image (ADR 0002). CI runs this on every PR (#81).
images-verify: ## Build both images and assert their deployment invariants
	./deploy/docker/verify-images.sh

# ─── Helm ─────────────────────────────────────────────────────────────────────

helm-verify: ## Lint the chart, render it, and assert the rendered manifests
	./deploy/helm/verify-chart.sh

helm-template: ## Render the chart with the example values, to stdout
	helm template icebergsst deploy/helm/icebergsst -f deploy/helm/example-values.yaml

# ─── Local stack ──────────────────────────────────────────────────────────────
# `up` waits for every healthcheck before migrating, so what it hands back is a
# stack that is ready rather than one that is merely started.

up: | .env ## Build and start the stack, then migrate
	$(COMPOSE) up -d --build --wait
	$(MAKE) migrate

down: ## Stop the stack and remove its containers
	$(COMPOSE) down

destroy: ## Stop the stack and delete its data volume
	$(COMPOSE) down --volumes

migrate: ## Apply migrations (api role only — it owns the schema)
	$(COMPOSE) run --rm api python -m iceberg_api migrate

seed: ## Load development fixtures (refuses to run in prod)
	$(COMPOSE) run --rm api python -m iceberg_api.seed

scale: ## Run N engine replicas (make scale N=4)
	$(COMPOSE) up -d --no-recreate --scale engine=$(N) engine

logs: ## Follow logs from every service
	$(COMPOSE) logs -f

ps: ## Show service status
	$(COMPOSE) ps

# ─── Secrets ──────────────────────────────────────────────────────────────────

init-env: .env ## Create .env from .env.example with generated secrets

# An order-only prerequisite in `up`, so an existing .env is left alone even when
# .env.example changes. The script refuses to overwrite one in any case: losing
# the master key makes every stored credential ref undecryptable.
.env:
	uv run python deploy/compose/init-env.py

secrets: ## Print a fresh master key and matching sealed pepper ref
	@key="$$(uv run python -m iceberg_core.secrets generate-master-key)"; \
	ref="$$(ICEBERG_MASTER_KEY=$$key uv run python -m iceberg_core.secrets generate-pepper)"; \
	printf 'ICEBERG_MASTER_KEY=%s\nICEBERG_FINGERPRINT_PEPPER_REF=%s\n' "$$key" "$$ref"

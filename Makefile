.PHONY: sync lint format type test check \
	up down logs migrate revision seed scale build verify-engine-image

COMPOSE := docker compose --env-file .env -f deploy/compose/docker-compose.yml
N ?= 1

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

# ─── Local stack (issue #21/#22) ─────────────────────────────────────────────

.env: ## Create .env from the template if it does not exist yet
	@test -f .env || (cp .env.example .env && \
		echo "Created .env from .env.example — replace the CHANGEME values before 'make up'.")

build: .env ## Build the api and engine images
	$(COMPOSE) build

up: .env ## Bring the stack up and wait for it to be healthy
	$(COMPOSE) up -d --wait

down: ## Tear the stack down (volumes survive; add -v to drop data)
	$(COMPOSE) down

logs: ## Follow logs from every service
	$(COMPOSE) logs -f

scale: .env ## Run N engine replicas, e.g. make scale N=3
	$(COMPOSE) up -d --wait --scale engine=$(N)

migrate: .env ## Apply migrations (api role only — engines never touch the DB)
	$(COMPOSE) run --rm api alembic upgrade head

revision: .env ## Autogenerate a migration, e.g. make revision M="add source"
	@test -n "$(M)" || (echo 'Give the revision a message: make revision M="add source"' && exit 1)
	@mkdir -p migrations/versions
	# --user so the generated file is owned by you, not by the image's uid 10001.
	$(COMPOSE) run --rm --user $$(id -u):$$(id -g) api alembic revision --autogenerate -m "$(M)"

seed: .env ## Seed development data (no-op until models land in M1)
	@echo "No seed data yet — models arrive with #31/#34."

verify-engine-image: ## Assert the engine image holds no DB driver or schema (ADR 0002)
	@echo "Checking the engine image for database access..."
	@$(COMPOSE) run --rm --no-deps --entrypoint sh engine -c \
		'! python -c "import asyncpg" 2>/dev/null && ! python -c "import sqlmodel" 2>/dev/null \
		 && ! test -e /app/alembic.ini && ! test -d /app/migrations' \
		&& echo "OK: no asyncpg, no sqlmodel, no migrations in the engine image." \
		|| (echo "FAIL: engine image contains database access — see ADR 0002." && exit 1)
	@echo "Checking the engine container has no Postgres credentials..."
	@$(COMPOSE) run --rm --no-deps --entrypoint sh engine -c 'env | grep -Ei "postgres|database"' \
		&& (echo "FAIL: engine environment carries database config." && exit 1) \
		|| echo "OK: no POSTGRES_*/DATABASE_* in the engine environment."

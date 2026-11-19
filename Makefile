# PayLineage. Run `make help` for targets.
SHELL := /bin/bash
.DEFAULT_GOAL := help
export PATH := $(CURDIR)/.tools/bin:$(PATH)
UV ?= uv
PY := $(UV) run python
PYTEST := $(UV) run pytest
TEST_DATABASE_URL ?= postgresql+psycopg://paylineage:paylineage_dev@localhost:5432/paylineage_test

.PHONY: help setup db-up db-down migrate policy-build policy-test policy-mutants parity vectors test-fast test-deep \
        mutation lint dev demo eval web-test e2e seed clean

help: ## Show targets
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n",$$1,$$2}'

setup: ## uv sync, pnpm install, pinned OPA, .env
	$(UV) sync
	pnpm install --frozen-lockfile
	./scripts/install_opa.sh
	@[ -f .env ] || cp .env.example .env

db-up: ## Start PostgreSQL in docker
	docker compose up -d postgres

db-down: ## Stop docker services
	docker compose down

migrate: ## Apply Alembic migrations to DATABASE_URL
	$(UV) run alembic -c backend/alembic.ini upgrade head

policy-build: ## Build policy/dist/policy.wasm and policy.sha256 (reproducible)
	$(PY) policy/scripts/build.py

policy-test: ## opa test against the exact staged build input
	$(PY) policy/scripts/build.py --stage-only >/dev/null
	opa fmt --list --fail policy/paylineage policy/tests
	opa check --strict policy/build/stage
	set -o pipefail; opa test policy/build/stage policy/tests --coverage --format=json | $(PY) policy/scripts/coverage_gate.py 95

policy-mutants: ## Hand-planted Rego mutants; every one must be killed
	$(PY) policy/scripts/rego_mutants.py

vectors: ## Regenerate shared decision and digest vectors
	$(PY) policy/scripts/gen_vectors.py
	$(PY) policy/scripts/gen_digest_vectors.py

parity: ## Shared vectors through Python and Node; must match
	$(PY) policy/scripts/parity.py

test-fast: policy-test policy-mutants parity ## PR level: unit, policy, parity, regression, small Hypothesis budget
	HYPOTHESIS_PROFILE=fast TEST_DATABASE_URL=$(TEST_DATABASE_URL) $(PYTEST) -q -m "not deep"
	pnpm -r --if-present test

test-deep: ## Nightly: large Hypothesis budget, stateful, concurrency, adversarial stub
	HYPOTHESIS_PROFILE=deep TEST_DATABASE_URL=$(TEST_DATABASE_URL) $(PYTEST) -q
	$(PY) -m paylineage.eval.run --tracks B C --extractor adversarial_stub

mutation: ## mutmut on policy adapter, approvals, permits, executor
	@echo "Python mutation testing is an open item: mutmut 3 cannot map mutants in this backend/src workspace (docs/EVALUATION_RESULTS.md)."
	@echo "Policy mutation testing runs in make policy-mutants."; exit 1

lint: ## ruff, mypy --strict, eslint, tsc --noEmit
	$(UV) run ruff check .
	$(UV) run ruff format --check .
	$(UV) run mypy
	pnpm -r --if-present lint
	pnpm -r --if-present typecheck

eval: ## Tracks B and C, all layers, writes eval/results
	$(PY) -m paylineage.eval.run --tracks B C

seed: ## Seed fictional demo data into DATABASE_URL
	$(PY) -m paylineage.db.seed

dev: ## backend + executor + mockbank + web locally
	./scripts/dev.sh

demo: ## Static demo export with the current policy.wasm
	pnpm --filter @paylineage/demo build

e2e: ## Playwright + axe against the static demo
	pnpm --filter @paylineage/demo e2e

clean:
	rm -rf policy/build .pytest_cache .mypy_cache .ruff_cache .hypothesis mutants

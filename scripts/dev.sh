#!/usr/bin/env bash
# Local stack without docker: API (8000), executor (8100), mock bank (8200), web (3000).
set -euo pipefail
cd "$(dirname "$0")/.."
export EXECUTOR_TOKEN="${EXECUTOR_TOKEN:-dev-executor-token}"
BANK_TOKEN="${MOCKBANK_TOKEN:-dev-bank-token}"
uv run alembic -c backend/alembic.ini upgrade head
trap 'kill 0' EXIT
MOCKBANK_TOKEN="$BANK_TOKEN" uv run paylineage-mockbank &
MOCKBANK_TOKEN="$BANK_TOKEN" MOCKBANK_URL=http://localhost:8200 uv run paylineage-executor &
env -u MOCKBANK_TOKEN uv run paylineage-api &
PAYLINEAGE_API_URL=http://localhost:8000 pnpm --filter @paylineage/web dev &
wait

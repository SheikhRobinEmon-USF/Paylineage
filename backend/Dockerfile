# syntax=docker/dockerfile:1.7
# One image for api, executor, mock bank, migrations and the simulated agent.
FROM python:3.12-slim-bookworm AS build
# Optional build secret `ca`: an extra CA bundle for TLS inspecting proxies.
#   docker build --secret id=ca,src=/path/to/ca.pem ...   (absent: public CAs only)
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca; fi; \
    pip install --no-cache-dir uv==0.11.32
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock ./
COPY backend/pyproject.toml backend/README.md backend/
COPY backend/src backend/src
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export SSL_CERT_FILE=/run/secrets/ca; fi; \
    uv sync --frozen --no-dev --no-editable --package paylineage --extra seed

FROM python:3.12-slim-bookworm
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
# Policy artifacts the runtime reads: the wasm and its hash, schemas, config (for the
# version label) and the shared vectors used by the startup self check.
COPY policy/dist/policy.wasm policy/dist/policy.sha256 policy/dist/
COPY policy/schema policy/schema
COPY policy/data policy/data
COPY policy/vectors policy/vectors
# Scenario templates and the frozen holdout lock, used by the seed.
COPY scenarios/templates scenarios/templates
COPY scenarios/holdout.lock.json scenarios/holdout.lock.json
COPY backend/alembic.ini backend/alembic.ini
COPY backend/alembic backend/alembic
RUN mkdir -p /app/var/checkpoints && chown -R app:app /app/var
# The package is installed non editable, so tell it where the checkout files are.
ENV PATH=/app/.venv/bin:$PATH \
    PAYLINEAGE_ROOT=/app \
    POLICY_DIR=/app/policy \
    AUDIT_CHECKPOINT_DIR=/app/var/checkpoints \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
USER app
EXPOSE 8000 8100 8200

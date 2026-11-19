# syntax=docker/dockerfile:1.7
FROM python:3.12-slim-bookworm AS build
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock ./
COPY backend/pyproject.toml backend/README.md backend/
COPY backend/src backend/src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim-bookworm
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY policy/dist policy/dist
COPY policy/schema policy/schema
COPY policy/vectors policy/vectors
COPY backend/alembic.ini backend/alembic.ini
COPY backend/alembic backend/alembic
ENV PATH=/app/.venv/bin:$PATH POLICY_DIR=/app/policy PYTHONUNBUFFERED=1
USER app
EXPOSE 8000 8100 8200

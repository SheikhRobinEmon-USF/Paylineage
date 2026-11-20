# syntax=docker/dockerfile:1.7
# PayLineage web app (Next.js standalone server). The API stays on its own origin
# behind the /v1 rewrite, so the session cookie remains SameSite=Strict.
FROM node:22.23-bookworm-slim AS build
ENV PNPM_HOME=/pnpm PATH=/pnpm:$PATH NEXT_TELEMETRY_DISABLED=1
RUN corepack enable
# Optional build secret `ca`: an extra CA bundle for TLS inspecting proxies.
#   docker build --secret id=ca,src=/path/to/ca.pem ...   (absent: public CAs only)
WORKDIR /repo
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json apps/web/
COPY packages/canonical/package.json packages/canonical/
COPY packages/policy-runtime/package.json packages/policy-runtime/
COPY packages/ui/package.json packages/ui/
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/ca; fi; \
    corepack install && pnpm install --frozen-lockfile --filter @paylineage/web...
COPY tsconfig*.json ./
COPY packages packages
# The UI imports the reason code registry from the policy schema (one source of truth).
COPY policy/schema policy/schema
COPY apps/web apps/web
# Rewrites are resolved at build time, so the API address is a build argument.
ARG PAYLINEAGE_API_URL=http://api:8000
ENV PAYLINEAGE_API_URL=$PAYLINEAGE_API_URL NEXT_OUTPUT=standalone
RUN pnpm --filter @paylineage/web build

FROM node:22.23-bookworm-slim
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=3000
WORKDIR /app
COPY --from=build --chown=node:node /repo/apps/web/.next/standalone ./
COPY --from=build --chown=node:node /repo/apps/web/.next/static ./apps/web/.next/static
USER node
EXPOSE 3000
CMD ["node", "apps/web/server.js"]

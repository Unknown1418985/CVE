# syntax=docker/dockerfile:1.7
# Builds one NestJS service (API Gateway or a backend microservice) from the monorepo.
#   docker build -f infra/docker/node-service.Dockerfile --build-arg PACKAGE=@cve/cve-service .

ARG NODE_IMAGE=node:22-alpine

FROM ${NODE_IMAGE} AS base
ENV PNPM_HOME=/pnpm PATH=/pnpm:$PATH CI=true
RUN corepack enable
WORKDIR /repo

# Prune the workspace to the target package and its internal dependencies.
FROM base AS pruner
ARG PACKAGE
COPY . .
RUN pnpm dlx turbo@2.11.10 prune "${PACKAGE}" --docker

FROM base AS builder
ARG PACKAGE
COPY --from=pruner /repo/out/json/ ./
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --frozen-lockfile
COPY --from=pruner /repo/out/full/ ./
COPY tsconfig.base.json tsconfig.nest.json ./
RUN pnpm turbo run build --filter="${PACKAGE}"
# Produce a self-contained production install of the package (workspace deps included).
RUN pnpm --filter "${PACKAGE}" deploy --legacy --prod /deploy

FROM ${NODE_IMAGE} AS runtime
ENV NODE_ENV=production
WORKDIR /app
RUN apk add --no-cache tini
COPY --from=builder --chown=node:node /deploy ./
USER node
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/main.js"]

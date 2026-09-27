# Build from the repository root:
# docker build -f apps/control-plane/Dockerfile -t <registry>/aidenid-control-plane:<tag> .
# The pinned digest follows the same Node 22 trust model as apps/dashboard/Dockerfile.
FROM node:22-bookworm-slim@sha256:689c11043dad91472750cd824c97dd5e2318e9dd6f954e492fe7af0135d33ceb AS builder

ARG PNPM_VERSION=10.28.0
WORKDIR /repo

RUN corepack enable \
  && corepack prepare "pnpm@${PNPM_VERSION}" --activate \
  && pnpm --version | grep -Fx "${PNPM_VERSION}"

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json tsconfig.test.json ./
COPY apps/control-plane/package.json apps/control-plane/tsconfig.json ./apps/control-plane/
COPY packages/common-schemas/package.json packages/common-schemas/tsconfig.json ./packages/common-schemas/
COPY packages/crypto/package.json packages/crypto/tsconfig.json ./packages/crypto/
COPY packages/eventing/package.json packages/eventing/tsconfig.json ./packages/eventing/
COPY packages/policy-engine/package.json packages/policy-engine/tsconfig.json ./packages/policy-engine/
COPY packages/transparency/package.json packages/transparency/tsconfig.json ./packages/transparency/
RUN pnpm install --ignore-scripts --frozen-lockfile
COPY apps/control-plane/src ./apps/control-plane/src
COPY apps/control-plane/migrations ./apps/control-plane/migrations
COPY apps/control-plane/certs ./apps/control-plane/certs
COPY packages/common-schemas/src ./packages/common-schemas/src
COPY packages/crypto/src ./packages/crypto/src
COPY packages/eventing/src ./packages/eventing/src
COPY packages/policy-engine/src ./packages/policy-engine/src
COPY packages/transparency/src ./packages/transparency/src
RUN pnpm --filter @aidenid/control-plane... build
RUN pnpm --filter @aidenid/control-plane deploy --prod --legacy /app

FROM node:22-bookworm-slim@sha256:689c11043dad91472750cd824c97dd5e2318e9dd6f954e492fe7af0135d33ceb AS runner

WORKDIR /app
ENV HOST=0.0.0.0
ENV NODE_ENV=production
ENV PORT=3000
ENV AIDENID_CONTROL_PLANE_DATABASE_SSLROOTCERT=/app/certs/rds-global-bundle.pem

COPY --chown=node:node --from=builder /app/package.json ./package.json
COPY --chown=node:node --from=builder /app/dist ./dist
COPY --chown=node:node --from=builder /app/migrations ./migrations
COPY --chown=node:node --from=builder /app/node_modules ./node_modules
COPY --chown=node:node --from=builder /repo/apps/control-plane/certs ./certs

EXPOSE 3000

USER node
CMD ["node", "dist/start.js"]

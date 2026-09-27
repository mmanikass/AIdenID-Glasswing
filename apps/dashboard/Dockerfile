# Build from the repository root:
# docker build -f apps/dashboard/Dockerfile -t <registry>/aidenid-dashboard:<tag> .
# The pinned digest is checked weekly by .github/workflows/dashboard-base-image-refresh.yml.
FROM node:22-bookworm-slim@sha256:689c11043dad91472750cd824c97dd5e2318e9dd6f954e492fe7af0135d33ceb AS builder

ARG PNPM_VERSION=10.28.0
WORKDIR /repo
ENV NEXT_TELEMETRY_DISABLED=1

RUN corepack enable \
  && corepack prepare "pnpm@${PNPM_VERSION}" --activate \
  && pnpm --version | grep -Fx "${PNPM_VERSION}"

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json tsconfig.test.json ./
COPY apps/dashboard/package.json apps/dashboard/tsconfig.json apps/dashboard/next-env.d.ts apps/dashboard/next.config.mjs ./apps/dashboard/
COPY packages/policy-engine/package.json packages/policy-engine/tsconfig.json ./packages/policy-engine/
RUN pnpm install --ignore-scripts --frozen-lockfile
COPY apps/dashboard/src ./apps/dashboard/src
COPY packages/policy-engine/src ./packages/policy-engine/src
RUN pnpm --filter @aidenid/policy-engine build
RUN pnpm --filter @aidenid/dashboard build

FROM node:22-bookworm-slim@sha256:689c11043dad91472750cd824c97dd5e2318e9dd6f954e492fe7af0135d33ceb AS runner

WORKDIR /app
ENV HOSTNAME=0.0.0.0
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000

COPY --chown=node:node --from=builder /repo/apps/dashboard/.next/standalone ./
COPY --chown=node:node --from=builder /repo/apps/dashboard/.next/static ./apps/dashboard/.next/static

EXPOSE 3000

USER node
CMD ["node", "apps/dashboard/server.js"]

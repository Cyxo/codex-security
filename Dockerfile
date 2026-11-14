# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

FROM node:26.13-bookworm-slim@sha256:bc0a2afd3b74ce12222fc8bab99271e66257f021078f5f4a5d687a77d280c1d9 AS base

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates git openssh-client python3 \
    && rm -rf /var/lib/apt/lists/*

FROM base AS package
WORKDIR /build/sdk/typescript

COPY package.json /build/package.json
COPY sdk/typescript/package.json sdk/typescript/pnpm-lock.yaml sdk/typescript/pnpm-workspace.yaml ./
COPY plugins/codex-security/mcp-app/package.json plugins/codex-security/mcp-app/pnpm-lock.yaml plugins/codex-security/mcp-app/pnpm-workspace.yaml /build/plugins/codex-security/mcp-app/

RUN npm install --global --no-audit --no-fund corepack@0.36.0 \
    && corepack enable \
    && corepack prepare "$(node --print 'require("/build/package.json").packageManager')" --activate \
    && pnpm install --frozen-lockfile \
    && pnpm --dir /build/plugins/codex-security/mcp-app install --frozen-lockfile

COPY sdk/typescript/ ./
COPY plugins/codex-security/ /build/plugins/codex-security/

RUN pnpm run types \
    && pnpm pack --pack-destination /build/package \
    && node scripts/check-package.mjs /build/package/*.tgz

FROM base AS runtime

LABEL org.opencontainers.image.title="Codex Security" \
      org.opencontainers.image.description="Codex Security scanner" \
      org.opencontainers.image.source="https://github.com/openai/codex-security"

COPY --chmod=0555 docker/entrypoint.sh /usr/local/bin/codex-security-entrypoint
COPY --chmod=0555 docker/git-credential.sh /usr/local/bin/codex-security-git-credential

# The entrypoint runs this wrapper when CS_COMPAT_BASE_URL names an
# OpenAI-compatible endpoint. It has no dependencies beyond Node.
COPY --chmod=0555 contrib/openai-compatible/bin/ /opt/codex-security-contrib/openai-compatible/bin/
COPY --chmod=0555 contrib/openai-compatible/src/ /opt/codex-security-contrib/openai-compatible/src/

ENV CS_COMPAT_WRAPPER=/opt/codex-security-contrib/openai-compatible/bin/cs-compat.mjs

# Drives a Lightpanda browser over CDP, for scans that assess a running web
# application. Node only; the browser is a separate service.
COPY --chmod=0555 contrib/web-probe/bin/ /opt/codex-security-contrib/web-probe/bin/
COPY --chmod=0555 contrib/web-probe/src/ /opt/codex-security-contrib/web-probe/src/
RUN ln -s /opt/codex-security-contrib/web-probe/bin/web-probe.mjs /usr/local/bin/web-probe

RUN groupadd --gid 10001 codex-security \
    && useradd --uid 10001 --gid 10001 --no-create-home codex-security \
    && mkdir -p /input /output /state \
    && chown 10001:10001 /output /state

ENV CODEX_SECURITY_STATE_DIR=/output/.codex-security-state \
    GIT_TERMINAL_PROMPT=0 \
    PYTHON=/usr/bin/python3

WORKDIR /state

ENTRYPOINT ["/usr/local/bin/codex-security-entrypoint"]
CMD ["--help"]

# Release builds supply a verified npm tarball and a frozen runtime lock.
FROM runtime AS scanner-release
RUN --mount=type=bind,from=release-inputs,target=/tmp/scanner,rw \
    cd /tmp/scanner \
    && npm ci --ignore-scripts --include=optional --no-audit --no-fund \
    && node node_modules/@openai/codex/bin/codex.js --version \
    && mkdir /opt/codex-security \
    && mv node_modules /opt/codex-security/ \
    && ln -s /opt/codex-security/node_modules/.bin/codex-security /usr/local/bin/codex-security \
    && ln -s /opt/codex-security/node_modules/.bin/cs /usr/local/bin/cs \
    && npm cache clean --force
ENV HOME=/state CODEX_HOME=/state
USER 10001:10001

# Local and pull request builds package the current checkout.
FROM runtime AS scanner
COPY --from=package /build/package/ /tmp/codex-security-package/

RUN npm install --global --include=optional --no-audit --no-fund \
        /tmp/codex-security-package/*.tgz \
    && node /usr/local/lib/node_modules/@openai/codex-security/node_modules/@openai/codex/bin/codex.js --version \
    && codex-security --version \
    && codex-security bulk-scan --help \
    && rm -rf /tmp/codex-security-package \
    && npm cache clean --force
ENV HOME=/state CODEX_HOME=/state
USER 10001:10001

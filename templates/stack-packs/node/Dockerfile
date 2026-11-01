# brakes stack-packs (node) — Seed: yours to edit; Dependabot bumps the digests.
# OpenShift: runs as an arbitrary non-root UID in group 0 (restricted SCC); USER is numeric.
# OpenShift: files are owned by root:0 and group-writable, so any UID in group 0 can use them.
# OpenShift: writes only under /tmp (HOME=/tmp); nothing is written under /app at runtime.
# Runtime: distroless nodejs{{tools.node}} (no shell); HEALTHCHECK uses node -e with fetch.
# ENTRYPOINT runs `index.js`: replace it with your server's entry file; add your build step after the install.
FROM {{image.build}} AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target={{cache}} \
    {{install}}

FROM {{image.runtime}}
WORKDIR /app
COPY --from=build --chown=0:0 --chmod=0775 /src /app
ENV HOME=/tmp
ENV NODE_ENV=production
USER 10001:0
EXPOSE {{port}}
{{healthcheck}}
ENTRYPOINT ["/nodejs/bin/node", "index.js"]

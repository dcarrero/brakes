# brakes stack-packs (rust) — Seed: yours to edit; Dependabot bumps the digests.
# OpenShift: runs as an arbitrary non-root UID in group 0 (restricted SCC); USER is numeric.
# OpenShift: files are owned by root:0 and group-writable, so any UID in group 0 can use them.
# OpenShift: writes only under /tmp (HOME=/tmp); nothing is written under /app at runtime.
# Runtime: distroless cc (glibc, no shell); HEALTHCHECK runs the binary's own `--healthcheck` flag.
FROM {{image.build}} AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin {{bin}} \
    && install -D -m 0755 target/release/{{bin}} /out/{{bin}}

FROM {{image.runtime}}
WORKDIR /app
COPY --from=build --chown=0:0 --chmod=0775 /out/{{bin}} /app/{{bin}}
ENV HOME=/tmp
USER 10001:0
EXPOSE {{port}}
{{healthcheck}}
ENTRYPOINT ["/app/{{bin}}"]

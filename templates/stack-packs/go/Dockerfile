# brakes stack-packs (go) — Seed: yours to edit; Dependabot bumps the digests.
# OpenShift: runs as an arbitrary non-root UID in group 0 (restricted SCC); USER is numeric.
# OpenShift: files are owned by root:0 and group-writable, so any UID in group 0 can use them.
# OpenShift: writes only under /tmp (HOME=/tmp); nothing is written under /app at runtime.
# Runtime: distroless static (CGO_ENABLED=0, no shell); HEALTHCHECK runs the binary's own `--healthcheck` flag.
# The build compiles the main package at the app root; point it at ./cmd/<name> if yours lives there.
FROM {{image.build}} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -mod=readonly -trimpath -o /out/{{bin}} .

FROM {{image.runtime}}
WORKDIR /app
COPY --from=build --chown=0:0 --chmod=0775 /out/{{bin}} /app/{{bin}}
ENV HOME=/tmp
USER 10001:0
EXPOSE {{port}}
{{healthcheck}}
ENTRYPOINT ["/app/{{bin}}"]

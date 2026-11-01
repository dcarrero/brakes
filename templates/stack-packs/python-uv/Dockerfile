# brakes stack-packs (python-uv) — Seed: yours to edit; Dependabot bumps the digests.
# OpenShift: runs as an arbitrary non-root UID in group 0 (restricted SCC); USER is numeric.
# OpenShift: files are owned by root:0 and group-writable, so any UID in group 0 can use them.
# OpenShift: writes only under /tmp (HOME=/tmp); bytecode is compiled at build, nothing is written under /app at runtime.
# Runtime: distroless python3 on Debian 13, Python {{tools.python}} like the build stage (no shell); HEALTHCHECK uses python3 -c.
# ENTRYPOINT runs `python3 -m app`: replace `app` with your package's module.
FROM {{image.build}} AS build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

FROM {{image.runtime}}
WORKDIR /app
COPY --from=build --chown=0:0 --chmod=0775 /src /app
ENV HOME=/tmp
ENV PYTHONPATH=/app:/app/.venv/lib/python{{tools.python}}/site-packages PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:0
EXPOSE {{port}}
{{healthcheck}}
ENTRYPOINT ["/usr/bin/python3", "-m", "app"]

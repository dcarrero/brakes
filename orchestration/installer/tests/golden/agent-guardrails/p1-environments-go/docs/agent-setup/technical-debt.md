# Technical debt

Last verified: 2026-10-30

Read this before imitating neighbouring code. It lists what an agent or a new
contributor must not copy even though the repository contains it, the commands that
work inside the development container, and the shortcuts that expire. The installer
seeds this file once; afterwards it belongs to the project and is edited by hand.

Keep every entry short and dated. When an entry is retired, delete it in the pull
request that closes its issue. When a section is empty, say so with a date, so a
reader can tell "nothing known" from "nobody looked".

## Patterns not to imitate

One row per pattern: where it lives, why it exists, what to do instead and the issue
that retires it.

| Pattern | Where | Why it exists | Instead | Retiring issue |
|---|---|---|---|---|

None yet (2026-10-28).

## Commands that work inside the container

Commands that differ from the declared ones when run in the development container or
an agent environment (missing tools, network limits, paths), with the reason.

| Command | Works instead of | Why |
|---|---|---|

None yet (2026-10-28).

## Shortcuts with an expiry

Temporary exceptions accepted on purpose: what was skipped, who accepted it and the
date after which it must be gone.

| Shortcut | Where | Accepted by | Expires | Retiring issue |
|---|---|---|---|---|

None yet (2026-10-28).

# ADR 0001: Dependency and image pinning

Status: accepted (Phase 0)

## Context

This server's security depends on exact behaviour of two libraries and one image:

- `pglast` — its parse tree is what the validator inspects. A change in how it represents a
  node can silently change what the validator allows.
- `mcp` — the SDK defines the protocol surface the model talks to.
- The Postgres server — enforces roles, grants, RLS and limits.

## Decision

1. **Resolution cutoff.** `[tool.uv] exclude-newer = "2026-10-26T00:00:00Z"`: no direct or
   transitive dependency newer than this date is resolved. New releases get time for problems
   to surface before we adopt them. `uv.lock` records exact versions and hashes; CI runs
   `uv sync --locked`.
2. **Exact pins** for `mcp==2.3.0` and `pglast==8.7`. Other dependencies use lower bounds and
   are fixed by the lock.
3. **Same Postgres major as the parser.** `pglast 8.7` bundles libpg_query for PostgreSQL 18.6
   (`pglast.parser.get_postgresql_version()` returns `(18, 6)`). The database therefore runs
   `postgres:18.6`, so the validator parses with the same grammar as the server — no parser
   differential.
4. **Image pinned by digest** in `docker-compose.yml` and `.github/workflows/ci.yml`:
   `postgres:18.6@sha256:e3d24f6906d0760bf4da0dae872415391ededefad23fd471c47dc53b0ddf3c42`
   (multi-arch index digest). A tag can be re-pointed; a digest cannot. GitHub Actions are
   likewise pinned to full commit SHAs.

## How to bump

1. Move the `exclude-newer` date forward, change the pin, run `uv lock`.
2. If `pglast` changes its bundled Postgres major, move the image to the same major (and
   re-check the PG data volume layout).
3. For the image: `docker buildx imagetools inspect postgres:<tag>`, copy the index `Digest`,
   update both files.
4. Run the full test suite (validator corpus included) before committing.

## Consequences

Security fixes in dependencies arrive only when the cutoff is bumped deliberately. That is the
trade-off for reproducible, reviewable upgrades.

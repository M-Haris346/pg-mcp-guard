"""Apply db/migrations/*.sql in order, as mcp_migrator, and install the context key.

Usage: uv run python scripts/migrate.py
Reads MIGRATOR_DATABASE_URL and MCP_CONTEXT_KEY from the environment / .env.

Each file runs in its own transaction and is recorded with its sha256. If an
already-applied file has changed on disk, nothing is applied and the script
fails: migrations are append-only.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import LiteralString, cast

import psycopg
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "db" / "migrations"

# Serialises concurrent runs (e.g. two test sessions). Arbitrary constant.
ADVISORY_LOCK_ID = 7_428_310_001

CREATE_TRACKING_TABLE = """
CREATE TABLE IF NOT EXISTS public.schema_migrations (
    filename   text PRIMARY KEY,
    sha256     text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
)
"""


class MigrationError(RuntimeError):
    pass


class MigrateSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    migrator_database_url: SecretStr
    mcp_context_key: SecretStr


def _discover(migrations_dir: Path) -> list[tuple[str, str]]:
    """Return (filename, body) for every NNN_*.sql file, in order."""
    files = sorted(migrations_dir.glob("[0-9][0-9][0-9]_*.sql"))
    if not files:
        raise MigrationError(f"no migrations found in {migrations_dir}")
    return [(f.name, f.read_text(encoding="utf-8")) for f in files]


def _sha256(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def apply_migrations(database_url: str, migrations_dir: Path = MIGRATIONS_DIR) -> list[str]:
    """Apply pending migrations. Returns the filenames applied (empty if none)."""
    migrations = _discover(migrations_dir)
    applied_now: list[str] = []

    with psycopg.connect(database_url, autocommit=True) as conn:
        conn.execute("SELECT pg_advisory_lock(%s)", (ADVISORY_LOCK_ID,))
        try:
            conn.execute(CREATE_TRACKING_TABLE)
            recorded = dict(
                conn.execute("SELECT filename, sha256 FROM public.schema_migrations").fetchall()
            )

            # Check every applied file first, so a tampered history applies nothing.
            for filename, body in migrations:
                if filename in recorded and recorded[filename] != _sha256(body):
                    raise MigrationError(f"{filename} changed after it was applied")

            for filename, body in migrations:
                if filename in recorded:
                    continue
                with conn.transaction():
                    # The body comes from a file in this repo, never from user
                    # input. No parameters: psycopg uses the simple query
                    # protocol, which allows the many statements a file holds.
                    conn.execute(cast(LiteralString, body))
                    conn.execute(
                        "INSERT INTO public.schema_migrations (filename, sha256) VALUES (%s, %s)",
                        (filename, _sha256(body)),
                    )
                applied_now.append(filename)
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (ADVISORY_LOCK_ID,))

    return applied_now


def install_context_key(database_url: str, key: bytes) -> None:
    """Upsert the single context-key row. Re-running with a new key rotates it."""
    if len(key) < 32:
        raise MigrationError("context key must be at least 32 bytes")
    with psycopg.connect(database_url) as conn:
        conn.execute(
            "INSERT INTO private.context_key (id, key) VALUES (true, %s)"
            " ON CONFLICT (id) DO UPDATE SET key = EXCLUDED.key",
            (key,),
        )


def main() -> int:
    settings = MigrateSettings()  # type: ignore[call-arg]
    url = settings.migrator_database_url.get_secret_value()
    try:
        key = bytes.fromhex(settings.mcp_context_key.get_secret_value())
    except ValueError:
        print("MCP_CONTEXT_KEY must be hex", file=sys.stderr)
        return 1

    try:
        applied = apply_migrations(url)
        install_context_key(url, key)
    except MigrationError as exc:
        print(f"migration failed: {exc}", file=sys.stderr)
        return 1

    print(f"applied: {', '.join(applied) if applied else 'nothing (up to date)'}", file=sys.stderr)
    print("context key installed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

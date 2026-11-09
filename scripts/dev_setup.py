"""One-command local setup: .env (only if missing), Postgres, migrations, seed.

Usage: uv run python scripts/dev_setup.py [--port 5432]

1. If .env does not exist, create it from .env.example with freshly generated
   random secrets (passwords, context key, JWT secret). An existing .env is
   never overwritten. Secrets are never printed.
2. docker compose up -d --wait db (starts Postgres and waits until healthy).
3. Test-connect with the .env credentials. If the data volume was created
   with other passwords, or before the set_config revoke, print the fix.
   This script never deletes anything (no `docker compose down -v`).
4. Run scripts/migrate.py and scripts/seed.py.
5. Print the next command (the demo).
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PLACEHOLDER = "change-me"
ROLE_PASSWORDS = {
    "mcp_migrator": "MCP_MIGRATOR_PASSWORD",
    "mcp_reader": "MCP_READER_PASSWORD",
    "mcp_auditor": "MCP_AUDITOR_PASSWORD",
}
_LINE = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")


def generate_secrets(
    token: Callable[[int], str] = secrets.token_urlsafe,
    hex_token: Callable[[int], str] = secrets.token_hex,
) -> dict[str, str]:
    """Fresh values for every change-me in .env.example (URL-safe characters only)."""
    values = {"POSTGRES_PASSWORD": token(24)}
    values.update({env: token(24) for env in ROLE_PASSWORDS.values()})
    values["MCP_CONTEXT_KEY"] = hex_token(32)  # 32 bytes, hex: what the server requires
    values["JWT_SECRET"] = token(48)  # 64 characters, well over the 32-byte minimum
    return values


def render_env(example: str, values: dict[str, str], *, port: int = 5432) -> str:
    """.env.example with every change-me replaced; database URLs get the same passwords."""
    out: list[str] = []
    for line in example.splitlines():
        match = _LINE.match(line)
        if match:
            name, value = match.groups()
            if value == PLACEHOLDER and name in values:
                line = f"{name}={values[name]}"
            elif name == "POSTGRES_PORT":
                line = f"POSTGRES_PORT={port}"
            elif name == "APP_ENV":
                line = "APP_ENV=dev"
            elif name.endswith("_DATABASE_URL"):
                for role, env in ROLE_PASSWORDS.items():
                    value = value.replace(f"{role}:{PLACEHOLDER}@", f"{role}:{values[env]}@")
                line = f"{name}={value.replace('127.0.0.1:5432/', f'127.0.0.1:{port}/')}"
        out.append(line)
    rendered = "\n".join(out) + "\n"
    leftover = [ln for ln in rendered.splitlines() if not ln.startswith("#") and PLACEHOLDER in ln]
    if leftover:
        raise ValueError(f"{len(leftover)} change-me value(s) left unreplaced in .env.example")
    return rendered


def write_env_if_missing(env_path: Path, example_path: Path, *, port: int = 5432) -> bool:
    """Create env_path from example_path. Returns False (and writes nothing) if it exists."""
    content = render_env(example_path.read_text(encoding="utf-8"), generate_secrets(), port=port)
    try:
        # O_EXCL: atomic "create, never overwrite", even if two runs race.
        fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    return True


def read_env(env_path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in env_path.read_text(encoding="utf-8").splitlines():
        match = _LINE.match(line.strip())
        if match:
            values[match.group(1)] = match.group(2)
    return values


def _run(*args: str) -> None:
    print(f"  $ {' '.join(args)}")
    subprocess.run(args, cwd=REPO, check=True)  # noqa: S603 - fixed argv


def check_database(env: dict[str, str]) -> list[str]:
    """Problems found when connecting with the .env credentials (empty = fine)."""
    import psycopg  # here: the .env-writing part of this script needs no driver

    problems: list[str] = []
    try:
        with psycopg.connect(env["MIGRATOR_DATABASE_URL"], connect_timeout=5) as conn:
            conn.execute("SELECT 1")
    except psycopg.OperationalError as exc:
        if "password authentication failed" in str(exc):
            problems.append(
                "The database volume was created with other passwords than this .env.\n"
                "    Fix: restore the .env that created it, or, if its data is disposable,\n"
                "    run `docker compose down -v` yourself (this deletes the volume) and rerun."
            )
        else:
            problems.append(f"Could not connect as mcp_migrator: {type(exc).__name__}")
        return problems
    try:
        with psycopg.connect(env["READER_DATABASE_URL"], connect_timeout=5) as conn:
            row = conn.execute(
                "SELECT has_function_privilege(current_user,"
                " 'pg_catalog.set_config(text,text,boolean)', 'EXECUTE')"
            ).fetchone()
        if row and row[0]:
            problems.append(
                "This volume predates the set_config revoke (the server would refuse to start).\n"
                "    Fix: docker compose exec -T db bash -s < db/upgrade/001_revoke_set_config.sh"
            )
    except psycopg.OperationalError as exc:
        problems.append(f"Could not connect as mcp_reader: {type(exc).__name__}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="One-command local setup.")
    parser.add_argument(
        "--port", type=int, default=5432, help="host port for Postgres in a new .env (default 5432)"
    )
    args = parser.parse_args(argv)
    # Our lines interleave with docker / migrate output: never hold them back.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    env_path, example_path = REPO / ".env", REPO / ".env.example"
    print("1/4 .env")
    if write_env_if_missing(env_path, example_path, port=args.port):
        print("  created .env with fresh random secrets (not shown)")
    else:
        print("  .env exists: left untouched")

    print("2/4 Postgres")
    _run("docker", "compose", "up", "-d", "--wait", "db")

    print("3/4 credentials")
    problems = check_database(read_env(env_path))
    for problem in problems:
        print(f"  PROBLEM: {problem}")
    if problems:
        return 1
    print("  connected as mcp_migrator and mcp_reader")

    print("4/4 migrations and demo data")
    _run(sys.executable, "scripts/migrate.py")
    _run(sys.executable, "scripts/seed.py")

    print("\nReady. Next: uv run python scripts/demo.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""DEV ONLY: mint a principal token for the stdio server.

Usage: uv run python -m scripts.mint_token --user alice --tenant acme [--ttl 1h]

Refuses to run unless APP_ENV=dev. Prints only the token on stdout (so it can
be captured or piped); every message goes to stderr. Reads JWT_SECRET,
JWT_ISSUER, JWT_AUDIENCE and JWT_MAX_LIFETIME_SECONDS from the environment /
.env, the same settings the server verifies with.

Whoever holds JWT_SECRET can mint any identity: this is a development helper
for the demo dataset, not an identity provider (ADR 0005).
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from uuid import UUID

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.auth import sign_token
from scripts.seed import ACME, ALICE, BOB, CAROL, GLOBEX, INITECH, MALLORY

USERS = {"alice": ALICE, "bob": BOB, "carol": CAROL, "mallory": MALLORY}
TENANTS = {"acme": ACME, "globex": GLOBEX, "initech": INITECH}
_TTL = re.compile(r"^(\d+)([smh])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600}


class MintSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "prod"
    jwt_secret: SecretStr
    jwt_issuer: str = "pg-mcp-guard"
    jwt_audience: str = "pg-mcp-guard"
    jwt_max_lifetime_seconds: int = 12 * 3600


def _uuid(value: str, names: dict[str, UUID]) -> UUID:
    if value in names:
        return names[value]
    return UUID(value)


def _ttl_seconds(value: str) -> int:
    match = _TTL.match(value)
    if match is None:
        raise ValueError("ttl must look like 30m, 1h or 900s")
    return int(match.group(1)) * _UNIT_SECONDS[match.group(2)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--user", required=True, help="alice | bob | carol | mallory | <uuid>")
    parser.add_argument("--tenant", required=True, help="acme | globex | initech | <uuid>")
    parser.add_argument("--ttl", default="1h", help="token lifetime, e.g. 30m, 1h (default 1h)")
    args = parser.parse_args(argv)

    settings = MintSettings()  # type: ignore[call-arg]
    if settings.app_env != "dev":
        print("refusing to mint: APP_ENV must be 'dev'", file=sys.stderr)
        return 2
    try:
        user_id = _uuid(args.user, USERS)
        tenant_id = _uuid(args.tenant, TENANTS)
        ttl = _ttl_seconds(args.ttl)
    except ValueError as exc:
        print(f"invalid argument: {exc}", file=sys.stderr)
        return 2
    if not 0 < ttl <= settings.jwt_max_lifetime_seconds:
        print(
            f"ttl must be between 1 s and {settings.jwt_max_lifetime_seconds} s"
            " (JWT_MAX_LIFETIME_SECONDS)",
            file=sys.stderr,
        )
        return 2

    token = sign_token(
        settings.jwt_secret.get_secret_value().encode(),
        user_id=user_id,
        tenant_id=tenant_id,
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        issued_at=int(time.time()),
        ttl_seconds=ttl,
    )
    print(token)
    return 0


if __name__ == "__main__":
    sys.exit(main())

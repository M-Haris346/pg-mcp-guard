"""Who is asking. The principal never comes from the model (CLAUDE.md rule 1).

stdio (Phase 4): one JWT, verified once at startup, gives the principal for the
whole process; its expiry is re-checked on every tool call. Tools take SQL or a
table name only, never identity. HTTP (Phase 5) verifies a token per request
with the same TokenVerifier interface.

HS256 with a shared secret is a deliberate demo choice (ADR 0005): the verifier
is pluggable, so an asymmetric / OIDC verifier can replace it without touching
the tools.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

import jwt

ALGORITHM = "HS256"
REQUIRED_CLAIMS = ("sub", "tenant_id", "iss", "aud", "exp", "iat")


@dataclass(frozen=True)
class Principal:
    user_id: UUID
    tenant_id: UUID


@dataclass(frozen=True)
class VerifiedToken:
    principal: Principal
    expires_at: int  # unix seconds, from the token's exp claim


class InvalidToken(Exception):
    """The token was missing, malformed or not acceptable. `reason` is safe to log."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class TokenVerifier(Protocol):
    def verify(self, token: str | None) -> VerifiedToken: ...


class HS256Verifier:
    def __init__(
        self,
        secret: bytes,
        *,
        issuer: str,
        audience: str,
        leeway_seconds: int = 30,
        max_lifetime_seconds: int = 12 * 3600,
    ) -> None:
        if len(secret) < 32:
            raise ValueError("JWT secret must be at least 32 bytes")
        self._secret = secret
        self._issuer = issuer
        self._audience = audience
        self._leeway = leeway_seconds
        self._max_lifetime = max_lifetime_seconds

    def verify(self, token: str | None) -> VerifiedToken:
        if not token:
            raise InvalidToken("missing")
        try:
            claims = jwt.decode(
                token,
                self._secret,
                # Only HS256: "none", other HMAC sizes and asymmetric algorithms
                # (key confusion) are refused before the signature is checked.
                algorithms=[ALGORITHM],
                issuer=self._issuer,
                audience=self._audience,
                leeway=self._leeway,
                options={"require": list(REQUIRED_CLAIMS)},
            )
        except jwt.ExpiredSignatureError:
            raise InvalidToken("expired") from None
        except jwt.ImmatureSignatureError:
            raise InvalidToken("not_yet_valid") from None
        except jwt.InvalidAudienceError:
            raise InvalidToken("wrong_audience") from None
        except jwt.InvalidIssuerError:
            raise InvalidToken("wrong_issuer") from None
        except jwt.MissingRequiredClaimError as exc:
            raise InvalidToken(f"missing_claim: {exc.claim}") from None
        except jwt.InvalidSignatureError:
            raise InvalidToken("bad_signature") from None
        except jwt.InvalidAlgorithmError:
            raise InvalidToken("algorithm_not_allowed") from None
        except jwt.InvalidTokenError:
            raise InvalidToken("malformed") from None

        exp, iat = claims["exp"], claims["iat"]
        if not isinstance(exp, int) or not isinstance(iat, int):
            raise InvalidToken("malformed")
        # Even a correctly signed token may not live longer than this: a leaked
        # long-lived token sitting in a client config is the realistic risk.
        if exp - iat > self._max_lifetime:
            raise InvalidToken("lifetime_too_long")

        try:
            user_id = UUID(str(claims["sub"]))
            tenant_id = UUID(str(claims["tenant_id"]))
        except ValueError:
            raise InvalidToken("invalid_subject_or_tenant") from None
        return VerifiedToken(principal=Principal(user_id, tenant_id), expires_at=exp)


def sign_token(
    secret: bytes,
    *,
    user_id: UUID,
    tenant_id: UUID,
    issuer: str,
    audience: str,
    issued_at: int,
    ttl_seconds: int,
) -> str:
    """Mint a token in the format HS256Verifier accepts (dev script and tests)."""
    claims = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "iss": issuer,
        "aud": audience,
        "iat": issued_at,
        "exp": issued_at + ttl_seconds,
    }
    return jwt.encode(claims, secret, algorithm=ALGORITHM)

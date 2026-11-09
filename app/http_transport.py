"""Streamable HTTP transport with a bearer token on every request (ADR 0006).

Built on the MCP SDK's own auth path:
    Starlette AuthenticationMiddleware(BearerAuthBackend(BearerTokenVerifier))
      -> AuthContextMiddleware (request token in a contextvar)
      -> RequireAuthMiddleware on /mcp (generic 401)
      -> body-size limit (413) -> session owner check (404) -> Host/Origin (421/403)
This module adds:
- BearerTokenVerifier: HS256 JWT checks (app/auth.py) plus a membership check,
  adapted to the SDK's TokenVerifier protocol;
- http_principal(): the principal of the message being handled, read from the
  SDK's per-request contextvar; tools and the ToolCallGuard use it;
- AuthFailureAudit: audits every 401 (rate-limited) with the internal reason;
- binding rules: loopback by default; anything else needs explicit opt-in.
TLS is out of scope: put a TLS-terminating reverse proxy in front.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import uvicorn
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.audit import write_auth_failure
from app.auth import HS256Verifier, InvalidToken, Principal, VerifiedToken
from app.config import Settings
from app.db import Pool, open_pools
from app.executor import Executor, ToolError
from app.log import get_logger
from app.server import create_server, run, startup_problem

log = get_logger("http")

# The SDK's AccessToken.client_id. All callers use the same "client" (this
# server's audience); identity is in subject, which includes the tenant so the
# SDK's session-owner check separates carol@acme from carol@globex.
CLIENT_ID = "pg-mcp-guard"
AUTH_AUDIT_PER_MINUTE = 60
AUTH_AUDIT_TIMEOUT_S = 2.0
LOOPBACK_HOSTS = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
LOOPBACK_ORIGINS = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]


# --- 401 reasons: from the verifier to the audit middleware ----------------------


@dataclass
class AuthOutcome:
    """Per-request holder. AuthFailureAudit puts a fresh one in the contextvar;
    the verifier only mutates it (never ContextVar.set), so the value survives
    however deep in the middleware stack the verifier runs."""

    reason: str | None = None


_auth_outcome: ContextVar[AuthOutcome | None] = ContextVar("mcp_guard_auth_outcome", default=None)


def note_auth_failure(reason: str) -> None:
    holder = _auth_outcome.get()
    if holder is not None:
        holder.reason = reason


# --- token verification ---------------------------------------------------------------

MembershipCheck = Callable[[Principal], Awaitable["bool | ToolError"]]


class BearerTokenVerifier:
    """The SDK's TokenVerifier protocol over HS256Verifier + a membership check.

    Never raises (an exception in an authentication backend would be a 500):
    every failure returns None, which the SDK answers with a generic 401, and
    records the internal reason for the audit.
    """

    def __init__(
        self,
        verifier: HS256Verifier,
        is_member: MembershipCheck,
        *,
        issuer: str,
        leeway_seconds: int,
        cache_seconds: float = 30.0,
        cache_size: int = 1024,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._verifier = verifier
        self._is_member = is_member
        self._issuer = issuer
        self._leeway = leeway_seconds
        self._cache_seconds = cache_seconds
        self._cache_size = cache_size
        self._clock = clock
        # (user, tenant) -> monotonic expiry of a *positive* check. Non-members
        # are never cached, so adding a membership takes effect at once.
        self._members: OrderedDict[tuple[UUID, UUID], float] = OrderedDict()

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            verified = self._verifier.verify(token)
        except InvalidToken as exc:
            note_auth_failure(exc.reason)
            return None
        except Exception as exc:  # never a 500 from authentication
            log.error("token_verification_failed", error=type(exc).__name__)
            note_auth_failure("internal_error")
            return None

        principal = verified.principal
        try:
            member = await self._member(principal)
        except Exception as exc:
            log.error("membership_check_failed", error=type(exc).__name__)
            member = ToolError("internal_error")
        if member is not True:
            note_auth_failure(
                "not_a_member" if member is False else f"membership_check_failed: {member.reason}"
            )
            return None

        return AccessToken(
            token=token,
            client_id=CLIENT_ID,
            scopes=[],
            # The SDK rejects expires_at < now with no leeway; ours allows the
            # configured leeway, so hand the SDK the same bound.
            expires_at=verified.expires_at + self._leeway,
            subject=f"{principal.user_id}/{principal.tenant_id}",
            claims={
                "iss": self._issuer,
                "sub": str(principal.user_id),
                "tenant_id": str(principal.tenant_id),
                "exp": verified.expires_at,
            },
        )

    async def _member(self, principal: Principal) -> bool | ToolError:
        key = (principal.user_id, principal.tenant_id)
        now = self._clock()
        cached = self._members.get(key)
        if cached is not None and cached > now:
            self._members.move_to_end(key)
            return True
        result = await self._is_member(principal)
        if result is True and self._cache_seconds > 0:
            self._members[key] = now + self._cache_seconds
            self._members.move_to_end(key)
            while len(self._members) > self._cache_size:
                self._members.popitem(last=False)
        elif cached is not None:
            self._members.pop(key, None)
        return result


def http_principal() -> VerifiedToken | None:
    """The principal of the request being handled right now.

    The SDK runs each message's handler in the contextvars of the HTTP request
    that carried it, so this is that request's token, not the session creator's.
    """
    access = get_access_token()
    claims = access.claims if access is not None else None
    if not claims:
        return None
    try:
        principal = Principal(UUID(claims["sub"]), UUID(claims["tenant_id"]))
        return VerifiedToken(principal=principal, expires_at=int(claims["exp"]))
    except (KeyError, ValueError, TypeError):
        return None


# --- 401 audit --------------------------------------------------------------------------


class TokenBucket:
    """At most `per_minute` events per minute, refilled continuously."""

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic) -> None:
        self._capacity = float(per_minute)
        self._tokens = float(per_minute)
        self._rate = per_minute / 60.0
        self._clock = clock
        self._last = clock()

    def take(self) -> bool:
        now = self._clock()
        self._tokens = min(self._capacity, self._tokens + (now - self._last) * self._rate)
        self._last = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


class AuthFailureAudit:
    """Outermost ASGI middleware: audit every 401 the SDK sends.

    The audit row is written after the response has gone out, so the client
    always gets the SDK's generic 401, never a 500, however the write goes. The
    write is bounded by `timeout_s`; a slower write finishes in the background.
    """

    def __init__(
        self,
        app: ASGIApp,
        auditor: Pool,
        *,
        per_minute: int = AUTH_AUDIT_PER_MINUTE,
        timeout_s: float = AUTH_AUDIT_TIMEOUT_S,
        acquire_timeout_s: float = 1.0,
    ) -> None:
        self.app = app
        self._auditor = auditor
        self._bucket = TokenBucket(per_minute)
        self._timeout_s = timeout_s
        self._acquire_timeout_s = acquire_timeout_s
        self._skipped = 0
        self._background: set[asyncio.Task[None]] = set()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        holder = AuthOutcome()
        context_token = _auth_outcome.set(holder)
        status: int | None = None

        async def watch(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
            await send(message)

        try:
            await self.app(scope, receive, watch)
        finally:
            _auth_outcome.reset(context_token)
        if status == 401:
            # No Authorization header (or not Bearer): the SDK never calls the
            # verifier, so no reason was recorded.
            await self._audit(f"invalid_token: {holder.reason or 'missing_token'}")

    async def _audit(self, reason: str) -> None:
        if not self._bucket.take():
            self._skipped += 1
            if self._skipped == 1 or self._skipped % 100 == 0:
                log.warning("auth_failure_audit_rate_limited", skipped=self._skipped)
            return
        task = asyncio.create_task(
            write_auth_failure(self._auditor, reason, acquire_timeout_s=self._acquire_timeout_s)
        )
        self._background.add(task)
        task.add_done_callback(self._finished)
        done, _ = await asyncio.wait({task}, timeout=self._timeout_s)
        if not done:
            log.error("auth_failure_audit_slow", timeout_s=self._timeout_s)

    def _finished(self, task: asyncio.Task[None]) -> None:
        self._background.discard(task)
        if not task.cancelled() and (error := task.exception()) is not None:
            log.error("auth_failure_audit_failed", error=type(error).__name__)


# --- binding ------------------------------------------------------------------------------


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def http_bind_problem(settings: Settings) -> str | None:
    """Why the configured bind address is refused, or None if it is fine."""
    if is_loopback(settings.mcp_http_host):
        return None
    if not settings.mcp_http_allow_remote:
        return "remote_bind_not_allowed: set MCP_HTTP_ALLOW_REMOTE=true to bind a non-loopback host"
    if not settings.mcp_http_allowed_hosts or not settings.mcp_http_allowed_origins:
        return "remote_bind_needs_allowed_hosts_and_origins"
    return None


@dataclass(frozen=True)
class HttpOptions:
    host: str = "127.0.0.1"
    port: int = 8765
    path: str = "/mcp"
    allowed_hosts: tuple[str, ...] = ()
    allowed_origins: tuple[str, ...] = ()
    max_body_bytes: int = 256 * 1024
    max_sessions: int = 100
    session_idle_s: float = 600.0

    @classmethod
    def from_settings(cls, settings: Settings) -> HttpOptions:
        return cls(
            host=settings.mcp_http_host,
            port=settings.mcp_http_port,
            path=settings.mcp_http_path,
            allowed_hosts=tuple(settings.mcp_http_allowed_hosts),
            allowed_origins=tuple(settings.mcp_http_allowed_origins),
            max_body_bytes=settings.mcp_http_max_body_bytes,
            max_sessions=settings.mcp_http_max_sessions,
            session_idle_s=settings.mcp_http_session_idle_s,
        )

    def transport_security(self) -> TransportSecuritySettings:
        """DNS-rebinding protection is always on: loopback lists by default,
        the configured lists for a remote bind (never silently off)."""
        loopback = is_loopback(self.host)
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(self.allowed_hosts) or (LOOPBACK_HOSTS if loopback else []),
            allowed_origins=list(self.allowed_origins) or (LOOPBACK_ORIGINS if loopback else []),
        )


def build_http_app(
    executor: Executor,
    verifier: BearerTokenVerifier,
    options: HttpOptions,
    *,
    leeway_seconds: int,
    clock: Callable[[], float] = time.time,
) -> ASGIApp:
    server = create_server(
        executor,
        http_principal,
        clock=clock,
        leeway_seconds=leeway_seconds,
        token_verifier=verifier,
        # The SDK requires an issuer URL in its auth settings. No OAuth
        # authorization server runs here (tokens are issued out of band), and
        # with resource_server_url=None no discovery metadata is published.
        auth=AuthSettings(
            issuer_url=f"http://{options.host}:{options.port}", resource_server_url=None
        ),
    )
    app = server.streamable_http_app(
        streamable_http_path=options.path,
        max_request_body_size=options.max_body_bytes,
        max_sessions=options.max_sessions,
        session_idle_timeout=options.session_idle_s,
        transport_security=options.transport_security(),
        host=options.host,
    )
    return AuthFailureAudit(
        app, executor.pools.auditor, acquire_timeout_s=executor.limits.pool_acquire_timeout_s
    )


def uvicorn_config(app: ASGIApp, options: HttpOptions) -> uvicorn.Config:
    return uvicorn.Config(
        app,
        host=options.host,
        port=options.port,
        # Our stderr JSON logging, not uvicorn's own config (which writes the
        # access log to stdout). No access log: one line per request is noise,
        # and nothing that could carry a header is ever logged.
        log_config=None,
        access_log=False,
        server_header=False,
        proxy_headers=False,
        lifespan="on",
        timeout_graceful_shutdown=5,
    )


async def serve_http(settings: Settings) -> int:
    try:
        pools = await open_pools(settings)
    except Exception as exc:
        log.error("startup_failed", reason="database_unavailable", error=type(exc).__name__)
        return 2
    try:
        executor = Executor(
            pools=pools, context_key=settings.context_key_bytes(), limits=settings.limits()
        )
        # Membership is checked per request (BearerTokenVerifier), not here.
        if (problem := await startup_problem(executor, None)) is not None:
            log.error("startup_failed", reason=problem)
            return 2
        verifier = BearerTokenVerifier(
            HS256Verifier(
                settings.jwt_secret_bytes(),
                issuer=settings.jwt_issuer,
                audience=settings.jwt_audience,
                leeway_seconds=settings.jwt_leeway_seconds,
                max_lifetime_seconds=settings.jwt_max_lifetime_seconds,
            ),
            executor.is_member,
            issuer=settings.jwt_issuer,
            leeway_seconds=settings.jwt_leeway_seconds,
            cache_seconds=settings.membership_cache_s,
            cache_size=settings.membership_cache_size,
        )
        options = HttpOptions.from_settings(settings)
        app = build_http_app(
            executor, verifier, options, leeway_seconds=settings.jwt_leeway_seconds
        )
        if not is_loopback(options.host):
            log.warning(
                "plain_http_on_non_loopback",
                host=options.host,
                hint="no TLS here: put a TLS-terminating reverse proxy in front",
            )
        log.info(
            "server_starting",
            transport="http",
            url=f"http://{options.host}:{options.port}{options.path}",
        )
        await uvicorn.Server(uvicorn_config(app, options)).serve()
        return 0
    finally:
        await pools.close()


def start_http(settings: Settings) -> int:
    if settings.mcp_principal_token:
        log.warning(
            "principal_token_ignored", reason="HTTP verifies a bearer token on every request"
        )
    if (problem := http_bind_problem(settings)) is not None:
        log.error("startup_failed", reason=problem)
        return 2
    return run(serve_http(settings))


__all__: list[Any] = [
    "AuthFailureAudit",
    "AuthOutcome",
    "BearerTokenVerifier",
    "HttpOptions",
    "TokenBucket",
    "build_http_app",
    "http_bind_problem",
    "http_principal",
    "is_loopback",
    "note_auth_failure",
    "serve_http",
    "start_http",
    "uvicorn_config",
]

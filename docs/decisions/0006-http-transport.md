# ADR 0006: Streamable HTTP with a bearer token per request; stdio vs HTTP trust

Status: accepted (Phase 5)

## Context

stdio (ADR 0005) serves one principal per process, and whoever runs the process holds every secret.
Phase 5 adds Streamable HTTP so that **one server process serves many principals**. Each caller
holds only its own short-lived token, and only the server holds `JWT_SECRET`, the context key and
the database passwords.

## Trust model: stdio vs HTTP

| | stdio | HTTP |
|---|---|---|
| Who holds `JWT_SECRET`, context key, DB passwords | the operator, who runs the server | the server only |
| Principal | one token, verified at startup, expiry re-checked per call | **the bearer token of every request** |
| What the token protects against | the *model* choosing or changing identity | the model **and other callers**: a caller can act only as its own token |
| Can the person running the client become someone else? | yes: they hold the secret and can mint any token | no, unless they obtain another caller's token |
| Membership | checked once at startup, then by RLS on every query | checked on every request (positive result cached ≤ 30 s, size-bounded), and by RLS on every query |

**In stdio mode the JWT is a guard against the model, not against the operator. In HTTP mode it is
also a guard between callers.** The data guarantees (RLS, grants, read-only, limits, audit) are the
same in both; only who is trusted with the secrets changes.

## Decisions

### Use the SDK's auth path (mcp 2.3.0), adapted, not replaced

`MCPServer(token_verifier=..., auth=AuthSettings(...)).streamable_http_app()` builds this chain,
outermost first:

1. Starlette `AuthenticationMiddleware(BearerAuthBackend)`, which calls our verifier;
2. `AuthContextMiddleware`, which puts the request's token in a contextvar;
3. `RequireAuthMiddleware` on `/mcp`, which answers a **generic 401** with
   `WWW-Authenticate: Bearer error="invalid_token"`;
4. the body-size limit (**413**);
5. the session-owner check (**404**);
6. the Host / Origin / Content-Type checks (**421 / 403 / 400**).

We add three pieces (`app/http_transport.py`):
- **`BearerTokenVerifier`.** It implements the SDK's `TokenVerifier` and reuses `HS256Verifier`:
  HS256 only, required claims, iss/aud, and the 12 h maximum lifetime. It then checks membership
  with the RLS helper. It never raises, because an exception in the authentication backend would be
  a 500; every failure is `None`, and the SDK turns that into the generic 401. The returned
  `AccessToken` has `subject = "<user>/<tenant>"`, so the SDK's session-owner check treats
  carol@acme and carol@globex as different principals.
- **`http_principal()`.** It reads `get_access_token()`. The SDK's dispatcher runs each message's
  handler in the contextvars of **the HTTP request that carried it**, so this is the current
  request's token, never the session creator's. `ToolCallGuard` and all three tools call it on
  every call.
- **`AuthFailureAudit`.** An outer ASGI middleware that audits every 401:
  - each row is `tool='http_auth'` (migration 006), user/tenant NULL (unverified claims are never
    trusted), and reason `invalid_token: <cause>`;
  - the cause travels from the verifier in a **per-request mutable holder**. The middleware sets the
    contextvar once; the verifier only mutates the holder;
  - the row is written **after** the response has gone out, so the client always gets the generic
    401, never a 500. The write is bounded at 2 s, and a slower write finishes in the background;
  - a token bucket of **60 rows/min** keeps an unauthenticated flood out of the audit table. The
    overflow is counted on stderr.

### The per-request principal is the guarantee; the session binding is defence in depth

Two protocol eras run side by side:
- **Modern (2026-07-28)**, the SDK client's default, has no session id. Every request stands alone,
  and its bearer token is the only identity.
- **Legacy** (`initialize` handshake) has a stateful session (`Mcp-Session-Id`). The SDK binds the
  session to the `(client_id, issuer, subject)` of the credential that created it, and any other
  credential gets 404 "Session not found".

These are tested:
- 20 concurrent calls each from alice@acme and bob@globex in one process, with the reader pool
  shared, in both eras: each sees only its own tenant;
- a session id reused with another principal's token gets 404, and so does carol@acme to
  carol@globex;
- **with the SDK's owner check monkeypatched off**, bob's token on alice's session sees only Globex
  rows, and the audit row names bob;
- a session created with short-lived token A and continued with token B (same principal): after A
  expires, B still works and A gets 401.

### Binding, transport security, limits

- **Loopback by default** (`127.0.0.1:8765`). Any other address needs `MCP_HTTP_ALLOW_REMOTE=true`
  **and** non-empty `MCP_HTTP_ALLOWED_HOSTS` / `MCP_HTTP_ALLOWED_ORIGINS`; otherwise the server
  refuses to start.
- **DNS-rebinding protection is always on.** We always pass `TransportSecuritySettings`, so it is
  never left to the SDK's host-name heuristic:
  - a Host that is not allowed gets 421, and a Host without a port fails the `host:*` patterns;
  - an Origin that is not allowed gets 403;
  - a missing Origin is accepted (non-browser clients).

  These checks run **after** authentication (SDK order), so an unauthenticated attempt gets 401
  first.
- **TLS is out of scope.** Over plain HTTP a bearer token can be read off the network, so remote use
  needs a TLS-terminating reverse proxy in front. The server logs a warning when bound to a
  non-loopback address.
- **Body limit 256 KiB** (the SDK's default is 4 MiB; a 20 000-character `sql` is about 85 KB as
  JSON). Over the limit gets **413 "Request body too large"**, by declared Content-Length or by
  counting a streamed body. It runs after auth, so no unauthenticated body is ever buffered.
- **Sessions:** at most 100 (beyond that **503**), idle timeout 10 min.
- **Cancellation:** `notifications/cancelled`, a client timeout, or a client that just disconnects
  all cancel the tool call. The executor audits it as `cancelled` and closes the connection rather
  than reusing it (ADR 0004).

### Logging

- Nothing that carries a header is logged. uvicorn runs with `access_log=False`, `log_config=None`
  (our stderr JSON) and `server_header=False`.
- A test runs the real server at `LOG_LEVEL=DEBUG` through authenticated calls, failed auth, a
  session hijack and a bad Host. It asserts that no token, no token signature, no `Bearer ` and no
  `authorization:` header appears in stdout or stderr. It fails when a token log line is injected,
  which was checked.
- `AccessToken.token` holds the raw token, so that object is never logged.

## Consequences and residual risks

- **HS256 is a shared secret.** The verifier can also mint. For real deployments, swap in an
  asymmetric or OIDC verifier; the `TokenVerifier` interface stays.
- **No OAuth discovery.** No authorization server runs here, and `resource_server_url` is unset, so
  no protected-resource metadata is published. Clients get their token out of band.
  `AuthSettings.issuer_url` is set only because the SDK requires it.
- **Revocation:**
  - a token stays valid until `exp` (at most 12 h), so keep TTLs short;
  - a removed membership gives zero rows at once (RLS), and 401 within the 30 s cache.
- **DoS:**
  - an unauthenticated request costs one HMAC check;
  - membership is cached;
  - sessions and the body size are capped;
  - the reader pool is small, so overload answers `unavailable`;
  - there is no per-client rate limit; that belongs in the reverse proxy.
- **SDK internals relied on, all pinned (`mcp==2.3.0`, ADR 0001) and tested:**
  - the per-message contextvar snapshot;
  - the session-owner check;
  - the `ServerMiddleware` hook.
- **The SDK logs some attacker-supplied values at WARNING** (an invalid Host or Origin, the first 64
  characters of a session id). These are not secrets.

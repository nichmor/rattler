# Auth Challenge Middleware — Design

**Date:** 2026-06-10
**Crate:** `rattler_networking`
**Motivation:** [pixi#6318](https://github.com/prefix-dev/pixi/issues/6318) — OIDC "repository access" never auto-authenticates for private channel *reads*. The existing `TrustedPublishingMiddleware` (added in rattler#2426) is channel-scoped, proactively mints, and has no consumers. This design replaces it with a host-scoped, challenge-reactive, pluggable middleware.

## Goals

1. **Per-host construction** — one middleware instance guards one server (scheme + host + port), not one channel path.
2. **Strict challenge-reactive minting** — a token is only acquired in response to a `WWW-Authenticate` header on a response. No speculative minting for public channels.
3. **Pluggable auth strategy** — a caller-supplied trait produces the token; OIDC trusted publishing is the first implementation, others (OAuth device flow, custom exchanges) can be added without touching the middleware.

## Non-goals / out of scope

- pixi wiring (lives in the pixi repo; the intended shape is one
  `AuthChallengeMiddleware` per prefix.dev host layered after
  `AuthenticationMiddleware` in `build_reqwest_clients`).
- prefix.dev server change to send `WWW-Authenticate` on anonymous
  private-channel access (server side; a hard dependency for the end-to-end
  fix of pixi#6318).
- The proactive upload path: `rattler_upload` keeps calling
  `check_trusted_publishing()` directly and is unchanged.
- Request-coalescing for concurrent first-mints (last-write-wins is correct,
  just occasionally redundant).

## Architecture

Two units with a strict boundary:

| Unit | Module | Owns | Knows nothing about |
|---|---|---|---|
| `AuthChallengeMiddleware`, `AuthFlow` trait, `Challenge`, `BearerToken`, token cache | `src/challenge_middleware.rs` (new) | HTTP mechanics: host matching, `WWW-Authenticate` parsing, caching, replay | OIDC, audiences, mint endpoints |
| `TrustedPublishingFlow` | `src/trusted_publishing.rs` (existing) | OIDC: `ambient-id` CI detection, mint exchange | Header parsing, caching, replay |

### Public API

```rust
/// One parsed challenge from a WWW-Authenticate header.
pub struct Challenge {
    pub scheme: String,                  // e.g. "Bearer"
    pub params: HashMap<String, String>, // realm, error, ...
}

#[async_trait]
pub trait AuthFlow: Send + Sync + fmt::Debug {
    /// Respond to challenges from the server. `Ok(None)` means "this flow
    /// does not apply here" (e.g. not running in CI); the middleware caches
    /// that negatively and stops asking.
    async fn acquire_token(
        &self,
        url: &Url,
        challenges: &[Challenge],
    ) -> Result<Option<BearerToken>, AuthFlowError>;
}

pub struct AuthChallengeMiddleware { /* host guard, Arc<dyn AuthFlow>, cache */ }

impl AuthChallengeMiddleware {
    /// `server` provides the scheme + host + port to guard. The path is ignored.
    pub fn new(server: Url, flow: Arc<dyn AuthFlow>) -> Self;
}
```

- `AuthFlowError` is a boxed-source error type (`thiserror`) so custom flows
  can surface arbitrary failures; the middleware only logs it, never
  propagates it.
- `BearerToken` is the current `TrustedPublishingToken` generalized: redacted
  `Debug`, `secret()` accessor, `Deserialize`-transparent.
- `TrustedPublishingToken` remains as a deprecated type alias of `BearerToken`
  (it appears in `rattler_upload` signatures).
- The token cache reuses today's logic verbatim: JWT `exp` parsing, 60-second
  refresh margin, `Disabled` negative state, `Arc<Mutex<…>>`.

### `TrustedPublishingFlow`

Constructed from `TrustedPublishingOptions` (audience + mint path; the
`for_prefix_dev()` defaults stay) plus a mint client. The mint client must not
itself layer in `AuthChallengeMiddleware`, or the mint call recurses — same
caveat as today, documented on the constructor.

Behavior: respond only to challenges whose scheme is `Bearer`
(case-insensitive); otherwise `Ok(None)`. On a Bearer challenge, run the
existing `get_token()` internals: `ambient-id` detection (returns `Ok(None)`
when no CI provider is present) then POST to the mint endpoint.

### Host matching

A request matches when scheme, host, and effective port (`port_or_known_default`)
all equal the configured server URL's. The scheme check ensures a token
acquired for `https://prefix.dev` is never replayed over plain `http`.
Path-prefix scoping from the old middleware is dropped deliberately: the
server scopes the minted token; client-side path guards added complexity
without real protection.

## Data flow

Per request through the middleware:

1. **Host mismatch, or `Authorization` already present** → pass through
   untouched. Credentials from `AuthenticationMiddleware` always win; never
   override or replay over them.
2. **Fresh cached token** → attach `Bearer` header (marked sensitive), send.
   After the first challenge, subsequent requests pay zero extra round trips.
3. **No token yet** → `try_clone()` the request *before* sending. Clone fails
   only for streaming bodies (absent on the GET-only read path); in that case
   send and pass the response through unmodified.
4. **Response carries a parseable `WWW-Authenticate` header** (401 or 403 —
   the header is the trigger, not the status code) and a clone is held:
   - Negative cache (`Disabled`) → return the server's response as-is.
   - Else call `flow.acquire_token(url, challenges)`:
     - `Ok(Some(token))` → cache, attach to clone, **replay once**, return the
       replayed response (even if it is another 401 — no loops).
     - `Ok(None)` → negative-cache, return original response.
     - `Err(e)` → `tracing::warn!`, negative-cache, return original response.
5. **Stale-token edge:** a challenge that arrives on a request that used a
   *cached* token means early revocation → clear cache, re-acquire once,
   replay once. A per-request replay flag guarantees at most one replay on
   every path.

### Error-handling principle

The middleware never converts an auth-attempt failure into a request failure.
If minting fails, the caller observes exactly what the server returned
(401/403) plus a warning log — identical observable behavior to not having
the middleware. Only infrastructure errors during the replay itself
(connection failures) propagate as middleware errors.

### Concurrency

`Arc<Mutex<TokenCache>>` as today. N parallel downloads racing on the first
challenge may mint concurrently; every minted token is valid and last write
wins. No coalescing lock in v1.

### Performance note

The first request to a private channel costs one extra round trip (the
challenge) plus one mint exchange — once per process per host, then cached.

## WWW-Authenticate parsing

Hand-rolled minimal RFC 7235 parser in `challenge_middleware.rs`:

- Handles multiple comma-separated challenges in one header value and the
  header appearing multiple times.
- Extracts scheme plus `key=value` / `key="quoted value"` auth-params; token68
  payloads are skipped (not needed for Bearer).
- Tolerant: malformed input yields fewer/no challenges, never an error or
  panic. No challenges parsed → middleware passes the response through.
- All parsed challenges are handed to the flow; the flow picks what it
  supports, keeping scheme knowledge out of the middleware.

## Deletions and compatibility

- **Deleted:** `TrustedPublishingMiddleware`, its `with_token` constructor,
  and the lazy/proactive state machinery. It shipped in `rattler_networking`
  0.28.0 with zero known consumers.
- **Unchanged:** `check_trusted_publishing()`, `get_token()`,
  `TrustedPublishingOptions`, `TrustedPublishResult`,
  `TrustedPublishingError` — `rattler_upload` compiles without modification.
- **Versioning:** breaking change → minor bump (0.28 → 0.29) via the normal
  release flow.
- **WASM:** same dual `#[cfg_attr]` async-trait treatment as the current
  middleware.

## Testing

**Unit (pure, no I/O):**
- Parser: single challenge (`Bearer realm="prefix.dev"`), multiple challenges
  in one header, multiple headers, garbage input → no challenges, no panic.
- Token cache: existing `jwt_expiration` / refresh-margin tests survive the
  move.

**Middleware (axum loopback + mock `AuthFlow`):**
- Challenge → flow called once → replay succeeds → next request reuses the
  cached token with zero additional flow calls or challenges.
- `Ok(None)` → negative-cached: flow called exactly once across many 401s.
- Non-matching host and scheme mismatch (`http` request vs `https` config) →
  untouched.
- Pre-existing `Authorization` header → pass through, no replay even on 401.
- Replay-once guard: server that always 401s → exactly one replay.
- Stale cached token → cache cleared, re-acquired, replayed once.

**`TrustedPublishingFlow` (axum mock mint endpoint):**
- Fake GitLab env (`PREFIX_DEV_ID_TOKEN`) → token minted and returned.
- Non-Bearer challenge → `Ok(None)`.
- Env-var tests run serially (`#[serial]` or process-wide lock) because
  `ambient-id` reads the process environment.

## Decisions log

| Decision | Choice | Why |
|---|---|---|
| Mint trigger | `WWW-Authenticate` header only (any status) | RFC-clean, self-describing; pairs with prefix.dev server fix; never mints speculatively |
| Scoping | Host-only (scheme+host+port), no path guard | Server scopes the token; client path guards were belt-and-suspenders complexity |
| Pluggability | Caller-supplied `AuthFlow` trait | Open extension point; middleware testable with mocks; OIDC becomes one impl |
| Old middleware | Delete, don't deprecate | Zero consumers, three weeks old; breaking now is nearly free |
| Structure | New generic middleware module + flow impl in `trusted_publishing.rs` | HTTP mechanics and OIDC specifics evolve independently |

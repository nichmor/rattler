# Auth Challenge Middleware Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `TrustedPublishingMiddleware` with a host-scoped, `WWW-Authenticate`-reactive `AuthChallengeMiddleware` driven by a pluggable `AuthFlow` strategy trait (spec: `docs/superpowers/specs/2026-06-10-auth-challenge-middleware-design.md`).

**Architecture:** A new module `crates/rattler_networking/src/challenge_middleware.rs` owns all HTTP mechanics (challenge parsing, token cache, request replay) behind an `AuthFlow` trait. `crates/rattler_networking/src/trusted_publishing.rs` keeps all OIDC specifics and gains `TrustedPublishingFlow`, the first `AuthFlow` implementation. The old middleware is deleted at the end.

**Tech Stack:** Rust, `reqwest-middleware`, `async-trait`, `thiserror`, `axum` + `tokio` (tests), `temp-env` (env-var tests), `ambient-id` (CI OIDC detection — already a dependency).

**Verified facts the plan relies on:**
- Nothing outside `rattler_networking` references `TrustedPublishingMiddleware` or `TrustedPublishingToken`. `rattler_upload` uses only `check_trusted_publishing`, `TrustedPublishResult`, `TrustedPublishingOptions` (`crates/rattler_upload/src/upload/prefix.rs:6-7`), and calls `.secret()` on the token inside `TrustedPublishResult::Configured` — preserved by `BearerToken`.
- `ambient-id` 0.0.11 GitLab detector triggers on env `GITLAB_CI` and reads the ID token from `<AUDIENCE>_ID_TOKEN` (e.g. `PREFIX_DEV_ID_TOKEN`), no HTTP involved. The GitHub detector triggers on `GITHUB_ACTIONS` — tests must explicitly unset it (rattler CI runs on GitHub Actions).
- `temp-env` has the `async_closure` feature enabled workspace-wide; `temp_env::async_with_vars` is already used in `s3_middleware.rs` tests.
- The crate has `#![deny(missing_docs)]` — every new `pub` item needs a doc comment.
- Run tests with `pixi run -- cargo nextest run -p rattler_networking <filter>`.

---

### Task 1: `Challenge` type and `WWW-Authenticate` parser

**Files:**
- Create: `crates/rattler_networking/src/challenge_middleware.rs`
- Modify: `crates/rattler_networking/src/lib.rs`

- [ ] **Step 1: Create the module skeleton and wire it into lib.rs**

Create `crates/rattler_networking/src/challenge_middleware.rs`:

```rust
//! Host-scoped middleware that reacts to `WWW-Authenticate` challenges by
//! acquiring a bearer token from a pluggable [`AuthFlow`] and replaying the
//! request once.
//!
//! [`AuthFlow`]: trait defined in this module; the first implementation is
//! [`crate::trusted_publishing::TrustedPublishingFlow`].

use std::collections::HashMap;

/// One parsed challenge from a `WWW-Authenticate` response header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The authentication scheme, e.g. `Bearer` (case preserved as sent).
    pub scheme: String,
    /// Auth parameters with lowercased keys, e.g. `realm` → `prefix.dev`.
    /// `token68` payloads (e.g. base64 blobs after the scheme) are skipped.
    pub params: HashMap<String, String>,
}
```

In `crates/rattler_networking/src/lib.rs`, add the module to the existing block of module declarations (after line 20, alphabetical position before `lazy_client`):

```rust
pub mod challenge_middleware;
```

- [ ] **Step 2: Write the failing parser tests**

Append to `challenge_middleware.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn header_map(values: &[&str]) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        for v in values {
            headers.append(
                http::header::WWW_AUTHENTICATE,
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn parses_single_bearer_challenge() {
        let challenges = parse_challenges(&header_map(&[r#"Bearer realm="prefix.dev""#]));
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].scheme, "Bearer");
        assert_eq!(challenges[0].params["realm"], "prefix.dev");
    }

    #[test]
    fn parses_multiple_challenges_in_one_header() {
        let challenges = parse_challenges(&header_map(&[
            r#"Bearer realm="prefix.dev", error="invalid_token", Basic realm="other""#,
        ]));
        assert_eq!(challenges.len(), 2);
        assert_eq!(challenges[0].scheme, "Bearer");
        assert_eq!(challenges[0].params["realm"], "prefix.dev");
        assert_eq!(challenges[0].params["error"], "invalid_token");
        assert_eq!(challenges[1].scheme, "Basic");
        assert_eq!(challenges[1].params["realm"], "other");
    }

    #[test]
    fn parses_multiple_headers() {
        let challenges =
            parse_challenges(&header_map(&[r#"Bearer realm="a""#, r#"Basic realm="b""#]));
        assert_eq!(challenges.len(), 2);
        assert_eq!(challenges[0].scheme, "Bearer");
        assert_eq!(challenges[1].scheme, "Basic");
    }

    #[test]
    fn quoted_commas_do_not_split_challenges() {
        let challenges = parse_challenges(&header_map(&[r#"Bearer realm="a,b""#]));
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].params["realm"], "a,b");
    }

    #[test]
    fn unquoted_params_and_case_insensitive_keys() {
        let challenges = parse_challenges(&header_map(&["Bearer REALM=prefix.dev"]));
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].params["realm"], "prefix.dev");
    }

    #[test]
    fn token68_payload_is_skipped_not_a_param() {
        // e.g. `Negotiate YII=` — the trailing blob is not a key=value param
        let challenges = parse_challenges(&header_map(&["Negotiate YII="]));
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].scheme, "Negotiate");
        assert!(challenges[0].params.is_empty());
    }

    #[test]
    fn garbage_yields_no_challenges_and_no_panic() {
        assert!(parse_challenges(&header_map(&["= = ="])).is_empty());
        assert!(parse_challenges(&header_map(&[",,,"])).is_empty());
        assert!(parse_challenges(&header_map(&[""])).is_empty());
        assert!(parse_challenges(&header_map(&["%%% ###"])).is_empty());
        assert!(parse_challenges(&http::HeaderMap::new()).is_empty());
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pixi run -- cargo nextest run -p rattler_networking challenge_middleware`
Expected: compile error — `parse_challenges` not found.

- [ ] **Step 4: Implement the parser**

Insert between the `Challenge` struct and the test module:

```rust
/// Parse all challenges from every `WWW-Authenticate` header in `headers`.
///
/// Tolerant by design: malformed input yields fewer (or no) challenges,
/// never an error or panic. Handles multiple comma-separated challenges in
/// one header value as well as the header appearing multiple times.
pub fn parse_challenges(headers: &http::HeaderMap) -> Vec<Challenge> {
    headers
        .get_all(http::header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(parse_header_value)
        .collect()
}

/// An auth scheme is a token of ASCII alphanumerics plus a few safe symbols.
/// Stricter than RFC 7235's `token` on purpose: it rejects line noise that
/// would otherwise be misread as a scheme.
fn is_valid_scheme(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn parse_header_value(value: &str) -> Vec<Challenge> {
    let mut challenges: Vec<Challenge> = Vec::new();
    for item in split_commas_respecting_quotes(value) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        // A new challenge starts with a scheme token; a continuation item is
        // a bare `key=value` auth-param belonging to the current challenge.
        let (first, rest) = match item.split_once(char::is_whitespace) {
            Some((first, rest)) => (first, Some(rest.trim())),
            None => (item, None),
        };
        if !first.contains('=') {
            if !is_valid_scheme(first) {
                continue;
            }
            challenges.push(Challenge {
                scheme: first.to_string(),
                params: HashMap::new(),
            });
            if let (Some(rest), Some(challenge)) = (rest, challenges.last_mut())
                && let Some((key, val)) = parse_param(rest)
            {
                challenge.params.insert(key, val);
            }
        } else if let Some(challenge) = challenges.last_mut()
            && let Some((key, val)) = parse_param(item)
        {
            challenge.params.insert(key, val);
        }
    }
    challenges
}

/// Parse one `key=value` or `key="quoted value"` auth-param. Returns `None`
/// for non-params (e.g. token68 blobs like `YII=`, which have an empty
/// "value" after the trailing `=`).
fn parse_param(s: &str) -> Option<(String, String)> {
    let (key, value) = s.split_once('=')?;
    let key = key.trim().to_ascii_lowercase();
    let value = value.trim();
    if key.is_empty() || value.is_empty() || !is_valid_scheme(&key) {
        return None;
    }
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    Some((key, value.replace("\\\"", "\"")))
}

/// Split on commas that are not inside a double-quoted string.
fn split_commas_respecting_quotes(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        match c {
            '\\' if in_quotes && !escaped => escaped = true,
            '"' if !escaped => {
                in_quotes = !in_quotes;
                escaped = false;
            }
            ',' if !in_quotes => {
                parts.push(&s[start..i]);
                start = i + 1;
                escaped = false;
            }
            _ => escaped = false,
        }
    }
    parts.push(&s[start..]);
    parts
}
```

Note: `let ... && let ...` chains require the crate's Rust 2024 edition (already set workspace-wide). If the installed toolchain rejects let-chains, nest the `if let`s instead.

- [ ] **Step 5: Run tests to verify they pass**

Run: `pixi run -- cargo nextest run -p rattler_networking challenge_middleware`
Expected: all 7 tests PASS.

- [ ] **Step 6: Commit**

```bash
pixi run -- cargo fmt -p rattler_networking
git add crates/rattler_networking/src/challenge_middleware.rs crates/rattler_networking/src/lib.rs
git commit -m "feat(networking): add WWW-Authenticate challenge parser"
```

---

### Task 2: `BearerToken` and token-cache primitives

**Files:**
- Modify: `crates/rattler_networking/src/challenge_middleware.rs`

These are the current `TrustedPublishingToken` / `jwt_expiration` / cached-token logic from `trusted_publishing.rs:98-150` and `260-284`, generalized. The originals stay in place until Task 7 (the old middleware still uses them); the duplication is temporary and deleted there.

- [ ] **Step 1: Write the failing tests**

Append inside the existing `mod tests` in `challenge_middleware.rs`:

```rust
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn bearer_token_debug_is_redacted() {
        let token = BearerToken::new("supersecret".to_string());
        let formatted = format!("{token:?}");
        assert!(!formatted.contains("supersecret"));
        assert!(formatted.contains("redacted"));
    }

    fn unsigned_jwt_with_exp(exp: u64) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{exp}}}"#));
        format!("{header}.{payload}.")
    }

    #[test]
    fn jwt_expiration_reads_exp_claim() {
        let token = unsigned_jwt_with_exp(1_700_000_000);
        assert_eq!(
            jwt_expiration(&token),
            UNIX_EPOCH.checked_add(Duration::from_secs(1_700_000_000))
        );
    }

    #[test]
    fn opaque_token_has_no_expiration() {
        assert_eq!(jwt_expiration("not-a-jwt"), None);
    }

    #[test]
    fn cached_jwt_is_stale_inside_refresh_margin() {
        let token = BearerToken::new(unsigned_jwt_with_exp(1_700_000_000));
        let cached = CachedToken::new(token);
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000 - 30);
        assert!(!cached.is_fresh(now));
        let earlier = UNIX_EPOCH + Duration::from_secs(1_700_000_000 - 3600);
        assert!(cached.is_fresh(earlier));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pixi run -- cargo nextest run -p rattler_networking challenge_middleware`
Expected: compile error — `BearerToken`, `jwt_expiration`, `CachedToken` not found.

- [ ] **Step 3: Implement token and cache primitives**

Add to the top of `challenge_middleware.rs` (imports section becomes):

```rust
use std::{
    collections::HashMap,
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use serde::Deserialize;
```

Add after the parser functions:

```rust
/// Refresh tokens this long before their `exp` so a token does not become
/// invalid while a request is in flight.
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// A short-lived bearer token acquired by an [`AuthFlow`].
///
/// `Deserialize`-transparent (a raw JSON string body deserializes directly
/// into it) and `Clone` so it can be shared between the cache and requests.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct BearerToken(String);

impl BearerToken {
    /// Wrap an existing token string.
    pub fn new(token: String) -> Self {
        Self(token)
    }

    /// The raw bearer token. Treat as sensitive; don't log it.
    pub fn secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BearerToken").field(&"<redacted>").finish()
    }
}

#[derive(Deserialize)]
struct JwtClaims {
    exp: Option<u64>,
}

/// Best-effort extraction of the `exp` claim from a JWT-shaped token.
/// Returns `None` for opaque tokens, which are then cached without expiry.
fn jwt_expiration(token: &str) -> Option<SystemTime> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| URL_SAFE.decode(payload))
        .ok()?;
    let claims: JwtClaims = serde_json::from_slice(&payload).ok()?;
    claims
        .exp
        .and_then(|exp| UNIX_EPOCH.checked_add(Duration::from_secs(exp)))
}

#[derive(Debug)]
struct CachedToken {
    token: BearerToken,
    expires_at: Option<SystemTime>,
}

impl CachedToken {
    fn new(token: BearerToken) -> Self {
        let expires_at = jwt_expiration(token.secret());
        Self { token, expires_at }
    }

    fn is_fresh(&self, now: SystemTime) -> bool {
        self.expires_at
            .is_none_or(|expires_at| now + TOKEN_REFRESH_MARGIN < expires_at)
    }
}

/// Cache state shared by all clones of one middleware instance.
#[derive(Debug, Default)]
enum TokenCache {
    /// No acquisition attempted yet.
    #[default]
    Empty,
    /// The flow reported "not applicable" or failed — stop asking.
    Disabled,
    /// A previously acquired token.
    Token(CachedToken),
}
```

`TokenCache` is `dead_code` until Task 4 — add `#[allow(dead_code)]` on it now and remove that attribute in Task 4.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pixi run -- cargo nextest run -p rattler_networking challenge_middleware`
Expected: all 11 tests PASS.

- [ ] **Step 5: Commit**

```bash
pixi run -- cargo fmt -p rattler_networking
git add crates/rattler_networking/src/challenge_middleware.rs
git commit -m "feat(networking): add BearerToken and token cache primitives"
```

---

### Task 3: `AuthFlow` trait, `AuthFlowError`, and re-exports

**Files:**
- Modify: `crates/rattler_networking/src/challenge_middleware.rs`
- Modify: `crates/rattler_networking/src/lib.rs`

Pure interface — no behavior to test beyond compilation; the trait is exercised by mock implementations in Task 4.

- [ ] **Step 1: Define the trait and error type**

Add to the imports in `challenge_middleware.rs`:

```rust
use thiserror::Error;
use url::Url;
```

Add after `BearerToken`'s `Debug` impl:

```rust
/// Error produced by an [`AuthFlow`] implementation.
///
/// Boxed so custom flows can surface arbitrary failures. The middleware only
/// logs this error and disables further attempts — it never propagates it,
/// so the caller always observes the server's original response.
#[derive(Debug, Error)]
#[error("authentication flow failed: {source}")]
pub struct AuthFlowError {
    #[source]
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl AuthFlowError {
    /// Wrap any error produced by an [`AuthFlow`] implementation.
    pub fn new(err: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>) -> Self {
        Self { source: err.into() }
    }
}

/// A pluggable strategy that turns a `WWW-Authenticate` challenge into a
/// bearer token.
///
/// Implementations decide which challenges they support (e.g. only scheme
/// `Bearer`) and how to acquire the token (OIDC exchange, device flow, ...).
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait AuthFlow: Send + Sync + fmt::Debug {
    /// Respond to `challenges` received from `url`.
    ///
    /// Return `Ok(None)` when this flow does not apply (e.g. unsupported
    /// scheme, or not running in a CI environment) — the middleware caches
    /// that negatively and stops asking for the lifetime of the process.
    async fn acquire_token(
        &self,
        url: &Url,
        challenges: &[Challenge],
    ) -> Result<Option<BearerToken>, AuthFlowError>;
}
```

- [ ] **Step 2: Re-export the main types from lib.rs**

In `crates/rattler_networking/src/lib.rs`, extend the `pub use` block at the top (after the `AuthenticationMiddleware` re-export on line 4):

```rust
pub use challenge_middleware::{AuthChallengeMiddleware, AuthFlow, AuthFlowError, BearerToken};
```

`AuthChallengeMiddleware` does not exist yet — to keep this step compiling, write the re-export without it for now:

```rust
pub use challenge_middleware::{AuthFlow, AuthFlowError, BearerToken};
```

(Task 4 adds `AuthChallengeMiddleware` to this list.)

- [ ] **Step 3: Verify it compiles cleanly**

Run: `pixi run -- cargo clippy -p rattler_networking --all-targets`
Expected: no errors. (`#![deny(missing_docs)]` will catch any missing doc comment.)

- [ ] **Step 4: Commit**

```bash
pixi run -- cargo fmt -p rattler_networking
git add crates/rattler_networking/src/challenge_middleware.rs crates/rattler_networking/src/lib.rs
git commit -m "feat(networking): add AuthFlow trait for pluggable challenge auth"
```

---

### Task 4: `AuthChallengeMiddleware` — challenge → acquire → replay, with caching

**Files:**
- Modify: `crates/rattler_networking/src/challenge_middleware.rs`
- Modify: `crates/rattler_networking/src/lib.rs`

- [ ] **Step 1: Write the failing tests (mock flows + three behaviors)**

Add inside `mod tests`:

```rust
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use reqwest_middleware::ClientBuilder;

    /// AuthFlow returning a fixed answer; counts invocations.
    #[derive(Debug)]
    struct StaticFlow {
        token: Option<&'static str>,
        calls: AtomicUsize,
    }

    impl StaticFlow {
        fn new(token: Option<&'static str>) -> Arc<Self> {
            Arc::new(Self {
                token,
                calls: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait::async_trait]
    impl AuthFlow for StaticFlow {
        async fn acquire_token(
            &self,
            _url: &Url,
            _challenges: &[Challenge],
        ) -> Result<Option<BearerToken>, AuthFlowError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.token.map(|t| BearerToken::new(t.to_string())))
        }
    }

    /// Axum server: requires `Bearer <accept>` on /channel/repodata.json,
    /// answers 401 + WWW-Authenticate otherwise. Counts every request.
    async fn spawn_protected_server(accept: &'static str, hits: Arc<AtomicUsize>) -> Url {
        use axum::{http::StatusCode, response::IntoResponse, routing::get};
        let router = axum::Router::new().route(
            "/channel/repodata.json",
            get(move |headers: axum::http::HeaderMap| {
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let expected = format!("Bearer {accept}");
                    match headers.get("authorization").and_then(|v| v.to_str().ok()) {
                        Some(auth) if auth == expected => {
                            (StatusCode::OK, "ok").into_response()
                        }
                        _ => (
                            StatusCode::UNAUTHORIZED,
                            [("www-authenticate", r#"Bearer realm="test""#)],
                            "unauthorized",
                        )
                            .into_response(),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Url::parse(&format!("http://{addr}")).unwrap()
    }

    fn client_with(middleware: AuthChallengeMiddleware) -> reqwest_middleware::ClientWithMiddleware {
        ClientBuilder::new(reqwest::Client::new())
            .with_arc(Arc::new(middleware))
            .build()
    }

    #[tokio::test]
    async fn challenge_triggers_mint_and_replay() {
        let hits = Arc::new(AtomicUsize::new(0));
        let server_url = spawn_protected_server("abc123", hits.clone()).await;
        let flow = StaticFlow::new(Some("abc123"));
        let client = client_with(AuthChallengeMiddleware::new(server_url.clone(), flow.clone()));

        let response = client
            .get(server_url.join("/channel/repodata.json").unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        assert_eq!(flow.calls.load(Ordering::SeqCst), 1);
        // one challenged request + one replay
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn second_request_reuses_cached_token_without_challenge() {
        let hits = Arc::new(AtomicUsize::new(0));
        let server_url = spawn_protected_server("abc123", hits.clone()).await;
        let flow = StaticFlow::new(Some("abc123"));
        let client = client_with(AuthChallengeMiddleware::new(server_url.clone(), flow.clone()));

        let url = server_url.join("/channel/repodata.json").unwrap();
        assert_eq!(client.get(url.clone()).send().await.unwrap().status(), 200);
        assert_eq!(client.get(url).send().await.unwrap().status(), 200);

        // flow consulted exactly once; second request went straight through
        assert_eq!(flow.calls.load(Ordering::SeqCst), 1);
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn inapplicable_flow_is_negative_cached() {
        let hits = Arc::new(AtomicUsize::new(0));
        let server_url = spawn_protected_server("abc123", hits.clone()).await;
        let flow = StaticFlow::new(None);
        let client = client_with(AuthChallengeMiddleware::new(server_url.clone(), flow.clone()));

        let url = server_url.join("/channel/repodata.json").unwrap();
        assert_eq!(client.get(url.clone()).send().await.unwrap().status(), 401);
        assert_eq!(client.get(url).send().await.unwrap().status(), 401);

        // flow consulted once, then disabled
        assert_eq!(flow.calls.load(Ordering::SeqCst), 1);
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }
```

Note on the mock's `async_trait` attribute: tests only compile/run on non-wasm targets, so the plain `#[async_trait::async_trait]` is correct there.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pixi run -- cargo nextest run -p rattler_networking challenge_middleware`
Expected: compile error — `AuthChallengeMiddleware` not found.

- [ ] **Step 3: Implement the middleware**

Extend imports in `challenge_middleware.rs`:

```rust
use std::sync::{Arc, Mutex};

use reqwest_middleware::{Middleware, Next};
```

Remove the `#[allow(dead_code)]` from `TokenCache` (added in Task 2). Add after `TokenCache`:

```rust
/// Outcome of a cache lookup, decoupled from the lock.
enum CacheLookup {
    Empty,
    Disabled,
    Fresh(BearerToken),
}

/// Host-scoped `reqwest` middleware that acquires a bearer token via an
/// [`AuthFlow`] when (and only when) the server answers with a
/// `WWW-Authenticate` challenge, then replays the request once.
///
/// Construct one instance per server. A request is in scope when its scheme,
/// host, and effective port match `server`; the path is ignored. Requests
/// that already carry an `Authorization` header are never touched, so
/// credentials from [`crate::AuthenticationMiddleware`] always win.
///
/// The first acquired token is cached (with JWT-expiry-aware refresh); a flow
/// that reports "not applicable" or fails disables the middleware for the
/// process lifetime. Acquisition failures are logged, never propagated: the
/// caller then observes the server's original 401/403 response.
#[derive(Clone, Debug)]
pub struct AuthChallengeMiddleware {
    server: Url,
    flow: Arc<dyn AuthFlow>,
    cache: Arc<Mutex<TokenCache>>,
}

impl AuthChallengeMiddleware {
    /// Create a middleware guarding the server identified by `server`'s
    /// scheme, host, and port. `server`'s path is ignored.
    pub fn new(server: Url, flow: Arc<dyn AuthFlow>) -> Self {
        Self {
            server,
            flow,
            cache: Arc::new(Mutex::new(TokenCache::Empty)),
        }
    }

    fn matches_host(&self, url: &Url) -> bool {
        url.scheme() == self.server.scheme()
            && url.host_str() == self.server.host_str()
            && url.port_or_known_default() == self.server.port_or_known_default()
    }

    fn lookup_cache(&self) -> CacheLookup {
        let cache = self
            .cache
            .lock()
            .expect("auth challenge token cache poisoned");
        match &*cache {
            TokenCache::Disabled => CacheLookup::Disabled,
            TokenCache::Token(cached) if cached.is_fresh(SystemTime::now()) => {
                CacheLookup::Fresh(cached.token.clone())
            }
            TokenCache::Empty | TokenCache::Token(_) => CacheLookup::Empty,
        }
    }

    /// Run the flow and record the outcome. `Ok(None)` and errors both
    /// disable the middleware; errors are additionally logged.
    async fn acquire_and_cache(&self, url: &Url, challenges: &[Challenge]) -> Option<BearerToken> {
        let result = self.flow.acquire_token(url, challenges).await;
        let mut cache = self
            .cache
            .lock()
            .expect("auth challenge token cache poisoned");
        match result {
            Ok(Some(token)) => {
                *cache = TokenCache::Token(CachedToken::new(token.clone()));
                Some(token)
            }
            Ok(None) => {
                tracing::debug!(
                    "AuthChallengeMiddleware: flow not applicable for {url}, disabling"
                );
                *cache = TokenCache::Disabled;
                None
            }
            Err(err) => {
                tracing::warn!(
                    "AuthChallengeMiddleware: failed to acquire token for {url}: {err}"
                );
                *cache = TokenCache::Disabled;
                None
            }
        }
    }
}

fn attach_bearer(
    req: &mut reqwest::Request,
    token: &BearerToken,
) -> reqwest_middleware::Result<()> {
    let bearer = format!("Bearer {}", token.secret());
    let mut value = reqwest::header::HeaderValue::from_str(&bearer)
        .map_err(reqwest_middleware::Error::middleware)?;
    value.set_sensitive(true);
    req.headers_mut()
        .insert(reqwest::header::AUTHORIZATION, value);
    Ok(())
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Middleware for AuthChallengeMiddleware {
    async fn handle(
        &self,
        mut req: reqwest::Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        if !self.matches_host(req.url())
            || req
                .headers()
                .contains_key(reqwest::header::AUTHORIZATION)
        {
            return next.run(req, extensions).await;
        }

        let cached = self.lookup_cache();
        if matches!(cached, CacheLookup::Disabled) {
            return next.run(req, extensions).await;
        }

        let used_cached_token = if let CacheLookup::Fresh(token) = &cached {
            attach_bearer(&mut req, token)?;
            true
        } else {
            false
        };

        // Clone before sending so we can replay on a challenge. Fails only
        // for streaming bodies (absent on the GET-only read path) — then the
        // response is passed through unmodified.
        let retry_req = req.try_clone();
        let url = req.url().clone();
        let response = next.clone().run(req, extensions).await?;

        let challenges = parse_challenges(response.headers());
        if challenges.is_empty() {
            return Ok(response);
        }
        let Some(mut retry_req) = retry_req else {
            return Ok(response);
        };

        if used_cached_token {
            // The server rejected a token we believed fresh (revoked early).
            // Drop it — and its header on the clone — before re-acquiring.
            *self
                .cache
                .lock()
                .expect("auth challenge token cache poisoned") = TokenCache::Empty;
            retry_req.headers_mut().remove(reqwest::header::AUTHORIZATION);
        }

        let Some(token) = self.acquire_and_cache(&url, &challenges).await else {
            return Ok(response);
        };
        attach_bearer(&mut retry_req, &token)?;
        // Replay exactly once; the replayed response is returned as-is even
        // if it is another challenge.
        next.run(retry_req, extensions).await
    }
}
```

Update the lib.rs re-export to its final form:

```rust
pub use challenge_middleware::{AuthChallengeMiddleware, AuthFlow, AuthFlowError, BearerToken};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pixi run -- cargo nextest run -p rattler_networking challenge_middleware`
Expected: all 14 tests PASS.

- [ ] **Step 5: Commit**

```bash
pixi run -- cargo fmt -p rattler_networking
git add crates/rattler_networking/src/challenge_middleware.rs crates/rattler_networking/src/lib.rs
git commit -m "feat(networking): add host-scoped challenge-reactive AuthChallengeMiddleware"
```

---

### Task 5: Guard and edge-case tests

**Files:**
- Modify: `crates/rattler_networking/src/challenge_middleware.rs` (tests, plus fixes if any test exposes a bug)

These behaviors were implemented in Task 4; this task pins them with regression tests. If any test fails, fix `handle()` — do not adjust the test expectations.

- [ ] **Step 1: Add the tests**

Add inside `mod tests`:

```rust
    /// AuthFlow yielding a different token per call (for the stale-token test).
    #[derive(Debug)]
    struct SequenceFlow {
        tokens: Mutex<Vec<&'static str>>,
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl AuthFlow for SequenceFlow {
        async fn acquire_token(
            &self,
            _url: &Url,
            _challenges: &[Challenge],
        ) -> Result<Option<BearerToken>, AuthFlowError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let token = self.tokens.lock().unwrap().remove(0);
            Ok(Some(BearerToken::new(token.to_string())))
        }
    }

    /// AuthFlow that always fails.
    #[derive(Debug)]
    struct FailingFlow {
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl AuthFlow for FailingFlow {
        async fn acquire_token(
            &self,
            _url: &Url,
            _challenges: &[Challenge],
        ) -> Result<Option<BearerToken>, AuthFlowError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(AuthFlowError::new(std::io::Error::other("mint exploded")))
        }
    }

    #[tokio::test]
    async fn non_matching_host_is_untouched() {
        let hits = Arc::new(AtomicUsize::new(0));
        let server_url = spawn_protected_server("abc123", hits.clone()).await;
        let flow = StaticFlow::new(Some("abc123"));
        let other_host = Url::parse("https://example.invalid").unwrap();
        let client = client_with(AuthChallengeMiddleware::new(other_host, flow.clone()));

        let response = client
            .get(server_url.join("/channel/repodata.json").unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 401);
        assert_eq!(flow.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn scheme_mismatch_is_untouched() {
        let hits = Arc::new(AtomicUsize::new(0));
        let server_url = spawn_protected_server("abc123", hits.clone()).await;
        // same host and port, but https configured vs the http test server
        let mut https_url = server_url.clone();
        https_url.set_scheme("https").unwrap();
        let flow = StaticFlow::new(Some("abc123"));
        let client = client_with(AuthChallengeMiddleware::new(https_url, flow.clone()));

        let response = client
            .get(server_url.join("/channel/repodata.json").unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 401);
        assert_eq!(flow.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn existing_authorization_header_is_respected() {
        let hits = Arc::new(AtomicUsize::new(0));
        let server_url = spawn_protected_server("abc123", hits.clone()).await;
        let flow = StaticFlow::new(Some("abc123"));
        let client = client_with(AuthChallengeMiddleware::new(server_url.clone(), flow.clone()));

        let response = client
            .get(server_url.join("/channel/repodata.json").unwrap())
            .header(reqwest::header::AUTHORIZATION, "Bearer user-supplied")
            .send()
            .await
            .unwrap();

        // wrong credentials stay wrong: no override, no replay
        assert_eq!(response.status(), 401);
        assert_eq!(flow.calls.load(Ordering::SeqCst), 0);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn replays_at_most_once() {
        let hits = Arc::new(AtomicUsize::new(0));
        // server accepts a token the flow never produces -> always 401
        let server_url = spawn_protected_server("never-issued", hits.clone()).await;
        let flow = StaticFlow::new(Some("abc123"));
        let client = client_with(AuthChallengeMiddleware::new(server_url.clone(), flow.clone()));

        let response = client
            .get(server_url.join("/channel/repodata.json").unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 401);
        // initial request + exactly one replay, nothing more
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(flow.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stale_cached_token_is_cleared_and_reacquired() {
        let hits = Arc::new(AtomicUsize::new(0));
        let server_url = spawn_protected_server("fresh", hits.clone()).await;
        let flow = Arc::new(SequenceFlow {
            tokens: Mutex::new(vec!["old", "fresh"]),
            calls: AtomicUsize::new(0),
        });
        let client = client_with(AuthChallengeMiddleware::new(server_url.clone(), flow.clone()));
        let url = server_url.join("/channel/repodata.json").unwrap();

        // Request 1: challenge -> flow mints "old" -> replay rejected (401).
        // "old" is now cached even though the server already rejects it,
        // simulating a token revoked after acquisition.
        assert_eq!(client.get(url.clone()).send().await.unwrap().status(), 401);

        // Request 2: cached "old" attached -> challenged -> cache cleared ->
        // flow mints "fresh" -> replay succeeds.
        assert_eq!(client.get(url).send().await.unwrap().status(), 200);

        assert_eq!(flow.calls.load(Ordering::SeqCst), 2);
        assert_eq!(hits.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn flow_error_is_swallowed_and_negative_cached() {
        let hits = Arc::new(AtomicUsize::new(0));
        let server_url = spawn_protected_server("abc123", hits.clone()).await;
        let flow = Arc::new(FailingFlow {
            calls: AtomicUsize::new(0),
        });
        let client = client_with(AuthChallengeMiddleware::new(server_url.clone(), flow.clone()));
        let url = server_url.join("/channel/repodata.json").unwrap();

        // caller sees the server's 401, not the flow error
        assert_eq!(client.get(url.clone()).send().await.unwrap().status(), 401);
        assert_eq!(client.get(url).send().await.unwrap().status(), 401);
        assert_eq!(flow.calls.load(Ordering::SeqCst), 1);
    }
```

- [ ] **Step 2: Run tests**

Run: `pixi run -- cargo nextest run -p rattler_networking challenge_middleware`
Expected: all 20 tests PASS. If one fails, the bug is in `handle()` from Task 4 — fix it there.

- [ ] **Step 3: Commit**

```bash
pixi run -- cargo fmt -p rattler_networking
git add crates/rattler_networking/src/challenge_middleware.rs
git commit -m "test(networking): pin AuthChallengeMiddleware guards and edge cases"
```

---

### Task 6: `TrustedPublishingFlow`

**Files:**
- Modify: `crates/rattler_networking/src/trusted_publishing.rs`

- [ ] **Step 1: Write the failing tests**

Add inside the existing `mod tests` in `trusted_publishing.rs`:

```rust
    use std::collections::HashMap;

    use crate::challenge_middleware::{AuthFlow, Challenge};

    fn bearer_challenge() -> Vec<Challenge> {
        vec![Challenge {
            scheme: "Bearer".to_string(),
            params: HashMap::new(),
        }]
    }

    fn plain_client() -> reqwest_middleware::ClientWithMiddleware {
        reqwest_middleware::ClientBuilder::new(reqwest::Client::new()).build()
    }

    #[tokio::test]
    async fn flow_ignores_non_bearer_challenges() {
        let flow = TrustedPublishingFlow::for_prefix_dev(plain_client());
        let challenges = vec![Challenge {
            scheme: "Basic".to_string(),
            params: HashMap::new(),
        }];
        let result = flow
            .acquire_token(
                &Url::parse("https://prefix.dev/channel/repodata.json").unwrap(),
                &challenges,
            )
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn flow_mints_token_via_gitlab_env() {
        use axum::{Json, routing::post};

        // Mint endpoint: verifies it receives the CI-provided OIDC token and
        // returns the minted bearer token as the raw response body.
        let router = axum::Router::new().route(
            "/api/oidc/mint_token",
            post(|Json(body): Json<serde_json::Value>| async move {
                assert_eq!(body["token"], "fake.oidc.token");
                "pfx-jwt.minted"
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let server_url = Url::parse(&format!("http://{addr}")).unwrap();

        // Force the GitLab detector: GITLAB_CI on, every other provider off.
        // (rattler's own CI runs on GitHub Actions, so GITHUB_ACTIONS must be
        // explicitly unset.)
        let token = temp_env::async_with_vars(
            [
                ("GITLAB_CI", Some("true")),
                ("PREFIX_DEV_ID_TOKEN", Some("fake.oidc.token")),
                ("GITHUB_ACTIONS", None),
                ("BUILDKITE", None),
                ("CIRCLECI", None),
            ],
            async {
                let flow = TrustedPublishingFlow::for_prefix_dev(plain_client());
                flow.acquire_token(
                    &server_url.join("/channel/repodata.json").unwrap(),
                    &bearer_challenge(),
                )
                .await
                .unwrap()
            },
        )
        .await;

        assert_eq!(token.expect("expected a minted token").secret(), "pfx-jwt.minted");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pixi run -- cargo nextest run -p rattler_networking trusted_publishing`
Expected: compile error — `TrustedPublishingFlow` not found.

- [ ] **Step 3: Implement `TrustedPublishingFlow`**

Add to `trusted_publishing.rs` imports:

```rust
use crate::challenge_middleware::{AuthFlow, AuthFlowError, Challenge};
```

Add after `get_publish_token` (before the old middleware code):

```rust
/// [`AuthFlow`] implementation backed by trusted publishing (CI OIDC).
///
/// Responds only to `Bearer` challenges. On a challenge it asks `ambient-id`
/// for an OIDC ID token (returns `Ok(None)` outside supported CI providers)
/// and exchanges it at the challenged host's mint endpoint
/// ([`TrustedPublishingOptions::mint_path`]). Because the surrounding
/// [`crate::AuthChallengeMiddleware`] is host-scoped, the challenged URL is
/// always the right host to mint against.
///
/// `client` is used only for the mint exchange; it must not itself layer in
/// [`crate::AuthChallengeMiddleware`] or the mint call will recurse.
#[derive(Debug, Clone)]
pub struct TrustedPublishingFlow {
    options: TrustedPublishingOptions,
    client: ClientWithMiddleware,
}

impl TrustedPublishingFlow {
    /// Create a flow with custom [`TrustedPublishingOptions`].
    pub fn new(options: TrustedPublishingOptions, client: ClientWithMiddleware) -> Self {
        Self { options, client }
    }

    /// Create a flow preconfigured for prefix.dev.
    pub fn for_prefix_dev(client: ClientWithMiddleware) -> Self {
        Self::new(TrustedPublishingOptions::for_prefix_dev(), client)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl AuthFlow for TrustedPublishingFlow {
    async fn acquire_token(
        &self,
        url: &Url,
        challenges: &[Challenge],
    ) -> Result<Option<crate::challenge_middleware::BearerToken>, AuthFlowError> {
        if !challenges
            .iter()
            .any(|challenge| challenge.scheme.eq_ignore_ascii_case("bearer"))
        {
            return Ok(None);
        }
        // `get_token` still returns the old `TrustedPublishingToken` until
        // Task 7 swaps it to `BearerToken`; convert explicitly for now.
        match get_token(&self.client, url, &self.options).await {
            Ok(Some(token)) => Ok(Some(crate::challenge_middleware::BearerToken::new(
                token.secret().to_string(),
            ))),
            Ok(None) => Ok(None),
            Err(err) => Err(AuthFlowError::new(err)),
        }
    }
}
```

Task 7 simplifies the `match` to `get_token(...).await.map_err(AuthFlowError::new)` once `get_token` natively returns `BearerToken`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pixi run -- cargo nextest run -p rattler_networking trusted_publishing`
Expected: all trusted_publishing tests PASS, including the two new ones. If `flow_mints_token_via_gitlab_env` fails on token detection, inspect `~/.cargo/registry/src/*/ambient-id-0.0.11/src/gitlab.rs` for the detector's env contract and adjust the env vars — do not loosen the assertions.

- [ ] **Step 5: Commit**

```bash
pixi run -- cargo fmt -p rattler_networking
git add crates/rattler_networking/src/trusted_publishing.rs
git commit -m "feat(networking): add TrustedPublishingFlow implementing AuthFlow"
```

---

### Task 7: Delete `TrustedPublishingMiddleware`, switch to `BearerToken`

**Files:**
- Modify: `crates/rattler_networking/src/trusted_publishing.rs`

- [ ] **Step 1: Delete the old middleware and its support code**

Remove from `trusted_publishing.rs` (line numbers refer to the pre-task state of the file; locate by name):

- `TrustedPublishingMiddleware` struct, its `impl` block, and its `Middleware` impl
- `TrustedPublishingState`, `TrustedPublishingCache`, `CachedTrustedPublishingToken`
- `TOKEN_REFRESH_MARGIN`, `JwtClaims`, `jwt_expiration`, `normalize_channel_url`
- The `TrustedPublishingToken` struct, its `impl`, and its `Debug` impl
- Tests: `token_debug_is_redacted`, `unsigned_jwt_with_exp`, `jwt_expiration_reads_exp_claim`, `cached_jwt_is_stale_inside_refresh_margin`, `middleware_injects_bearer_for_matching_host`, `middleware_skips_same_host_different_channel`, `normalize_channel_url_adds_trailing_slash`, `middleware_skips_non_matching_host`
- Now-unused imports: the `base64` block, `Arc`/`Mutex`, `Duration`/`SystemTime`/`UNIX_EPOCH`, `Middleware`/`Next`, `Deserialize`

- [ ] **Step 2: Replace the token type with `BearerToken` + deprecated alias**

Where `TrustedPublishingToken` was defined, add instead:

```rust
/// Deprecated alias kept for backwards compatibility.
#[deprecated(note = "use `rattler_networking::BearerToken` instead")]
pub type TrustedPublishingToken = BearerToken;
```

Then switch internal uses to `BearerToken` (the deprecated alias must not be used internally, or the build warns):

- Import: extend the existing `use crate::challenge_middleware::…` line to include `BearerToken`.
- `TrustedPublishResult::Configured(TrustedPublishingToken)` → `Configured(BearerToken)`
- `get_token(...) -> Result<Option<TrustedPublishingToken>, ...>` → `Result<Option<BearerToken>, ...>`
- `get_publish_token(...) -> Result<TrustedPublishingToken, ...>` → `Result<BearerToken, ...>`
- In `get_publish_token`'s success arm, the private-field constructor no longer exists:
  ```rust
  Ok(BearerToken::new(String::from_utf8_lossy(&body).to_string()))
  ```
- Simplify `TrustedPublishingFlow::acquire_token` back to the one-liner now that types align:
  ```rust
  get_token(&self.client, url, &self.options)
      .await
      .map_err(AuthFlowError::new)
  ```
- Update the module doc comment (lines 1-9) to mention that challenge-reactive read auth lives in [`crate::challenge_middleware`] and this module owns the OIDC exchange plus `TrustedPublishingFlow`.

- [ ] **Step 3: Verify the whole crate and dependents still build and pass**

Run: `pixi run -- cargo nextest run -p rattler_networking`
Expected: PASS (all remaining trusted_publishing tests + all 20 challenge_middleware tests + the rest of the crate's suite).

Run: `pixi run -- cargo check -p rattler_upload`
Expected: clean — `rattler_upload` compiles unmodified against `BearerToken` via `TrustedPublishResult`.

- [ ] **Step 4: Commit**

```bash
pixi run -- cargo fmt -p rattler_networking
git add crates/rattler_networking/src/trusted_publishing.rs
git commit -m "feat(networking)!: remove TrustedPublishingMiddleware in favor of AuthChallengeMiddleware

BREAKING CHANGE: TrustedPublishingMiddleware is replaced by the host-scoped,
WWW-Authenticate-reactive AuthChallengeMiddleware with the pluggable AuthFlow
trait. TrustedPublishingToken is now a deprecated alias of BearerToken."
```

---

### Task 8: Full verification

**Files:** none new — workspace-level checks.

- [ ] **Step 1: Full workspace lint and format**

Run: `pixi run cargo-fmt`
Expected: no diff.

Run: `pixi run cargo-clippy`
Expected: no warnings/errors.

- [ ] **Step 2: Full crate test suites for the touched dependency chain**

Run: `pixi run -- cargo nextest run -p rattler_networking -p rattler_upload`
Expected: PASS.

- [ ] **Step 3: Commit any lint/format fallout**

```bash
git add -A
git commit -m "chore(networking): fmt and clippy fixes for challenge middleware" || echo "nothing to commit"
```

---

## Spec coverage map

| Spec requirement | Task |
|---|---|
| `Challenge` type + tolerant RFC 7235 parser, multi-challenge, multi-header | 1 |
| `BearerToken` (redacted Debug, `secret()`, serde-transparent), JWT-exp cache, 60s margin, `Disabled` state | 2 |
| `AuthFlow` trait, `AuthFlowError` (boxed, logged-not-propagated), lib re-exports | 3 |
| Host matching (scheme+host+port), challenge → acquire → replay-once, token reuse, negative cache | 4 |
| Authorization-header precedence, scheme/host guards, replay-once cap, stale-token re-acquire, error swallowing | 5 |
| `TrustedPublishingFlow` (Bearer-only, ambient-id + mint via challenged URL), mint-client recursion caveat documented | 6 |
| Delete old middleware, deprecated `TrustedPublishingToken` alias, `rattler_upload` unaffected | 7 |
| WASM `cfg_attr` parity | 3, 4, 6 (each async_trait site) |
| Version bump 0.28 → 0.29 | handled by release automation, not in this plan |

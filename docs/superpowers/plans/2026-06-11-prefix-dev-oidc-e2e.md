# prefix.dev OIDC End-to-End Test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A CI job proving the challenge-reactive OIDC read path end to end against beta.prefix.dev, plus the reference CLI wiring of `AuthChallengeMiddleware` (spec: `docs/superpowers/specs/2026-06-11-prefix-dev-oidc-e2e-design.md`).

**Architecture:** `TrustedPublishingOptions::for_host` makes the OIDC audience follow the server host; `rattler_upload` and a new channel-aware client constructor in `rattler-bin` both use it (the latter scoped to `prefix.dev`/`*.prefix.dev` hosts). A nushell e2e script mints independently, uploads via the proactive path, asserts the server fires `WWW-Authenticate`, then reads via the challenge-reactive path through the `rattler` CLI; a GitHub Actions workflow runs it with `id-token: write`.

**Tech Stack:** Rust (`rattler_networking`, `rattler_upload`, `rattler-bin`), nushell ≥0.106 (`http` builtins), pixi feature/environment, GitHub Actions OIDC.

**Branch:** `auth-challenge-e2e` (stacked on `auth-challenge-middleware`; PR after conda/rattler#2504 merges).

**Verified facts the plan relies on:**
- `rattler upload prefix` flags: `--url <Url>` (default `https://prefix.dev`), `--channel <String>`, `--skip-existing` (`crates/rattler_upload/src/upload/opt.rs:245-292`); the subcommand is wired in `crates/rattler-bin/src/main.rs:60,127`.
- `rattler_upload/src/upload/prefix.rs` has TWO `TrustedPublishingOptions::for_prefix_dev()` call sites (one per `sigstore-sign` cfg branch), both passing `&prefix_data.url` as the mint server.
- In `crates/rattler-bin/src/commands/create.rs`, `channels: Vec<Channel>` (rattler_conda_types) is resolved at ~line 166, BEFORE `create_client_with_middleware()` at line 182. `Channel.base_url: ChannelUrl` implements `AsRef<Url>`.
- The pixi e2e pattern: a feature with `rattler = { path = "crates/rattler-bin" }` + `nushell` deps, a task running `nu scripts/e2e/<name>.nu`, and an environment (see `[feature.s3]` / `[feature.minio]` in `pixi.toml:90-115`). Adding a feature/environment REQUIRES regenerating `pixi.lock` — in this one case staging `pixi.lock` is intentional and required (CI's setup-pixi fails on an out-of-date lockfile).
- Workflow template: `.github/workflows/e2e-s3-tests.yml` (pinned action SHAs to copy verbatim).
- Test package: `test-data/packages/empty-0.1.0-h4616a5c_0.conda` (noarch, package `empty==0.1.0`).
- Crates lint gate: `cargo clippy -p <crate> --all-targets -- -D warnings`; `rattler_networking` and `rattler-bin` both have `#![deny(missing_docs)]`? — `rattler_networking` does; `rattler-bin` is a binary crate without it, but keep doc comments on new pub items anyway.
- Package names: `rattler-bin` (binary name `rattler`), `rattler_networking`, `rattler_upload`.

---

### Task 1: `TrustedPublishingOptions::for_host`

**Files:**
- Modify: `crates/rattler_networking/src/trusted_publishing.rs`

- [ ] **Step 1: Write the failing tests**

Add inside the existing `mod tests` in `trusted_publishing.rs`:

```rust
    #[test]
    fn for_host_derives_audience_from_host() {
        let options = TrustedPublishingOptions::for_host(
            &Url::parse("https://beta.prefix.dev/some-channel/noarch/repodata.json").unwrap(),
        )
        .unwrap();
        assert_eq!(options.audience, "beta.prefix.dev");
        assert_eq!(options.mint_path, "/api/oidc/mint_token");

        let prod = TrustedPublishingOptions::for_host(&Url::parse("https://prefix.dev").unwrap())
            .unwrap();
        assert_eq!(prod.audience, TrustedPublishingOptions::for_prefix_dev().audience);
        assert_eq!(prod.mint_path, TrustedPublishingOptions::for_prefix_dev().mint_path);
    }

    #[test]
    fn for_host_returns_none_without_host() {
        // data: URLs have no host component
        let url = Url::parse("data:text/plain,hello").unwrap();
        assert!(TrustedPublishingOptions::for_host(&url).is_none());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pixi run -- cargo nextest run -p rattler_networking for_host`
Expected: compile error — `for_host` not found.

- [ ] **Step 3: Implement**

Add to the `impl TrustedPublishingOptions` block (next to `for_prefix_dev`):

```rust
    /// Options for any trusted-publishing server following the prefix.dev
    /// convention: the OIDC audience is the server's host name and tokens
    /// are minted at `/api/oidc/mint_token`.
    ///
    /// Returns `None` when `server` has no host (e.g. `data:` URLs).
    ///
    /// Deriving the audience from the host scopes each OIDC ID token to the
    /// server it is sent to: a token minted with `aud = <host>` is only
    /// redeemable at that host.
    pub fn for_host(server: &Url) -> Option<Self> {
        Some(Self {
            audience: server.host_str()?.to_string(),
            mint_path: "/api/oidc/mint_token".to_string(),
        })
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pixi run -- cargo nextest run -p rattler_networking trusted_publishing`
Expected: all pass including the 2 new tests.
Also: `cargo clippy -p rattler_networking --all-targets -- -D warnings` → clean.

- [ ] **Step 5: Commit**

```bash
pixi run -- cargo fmt -p rattler_networking
git add crates/rattler_networking/src/trusted_publishing.rs
git commit -m "feat(networking): add TrustedPublishingOptions::for_host"
```

---

### Task 2: `rattler_upload` derives the audience from the upload host

**Files:**
- Modify: `crates/rattler_upload/src/upload/prefix.rs`

Mechanical change (behavior covered by the e2e job; no practical unit seam here — `check_trusted_publishing` needs a live CI env).

- [ ] **Step 1: Replace both call sites**

In `crates/rattler_upload/src/upload/prefix.rs` there are two occurrences (one in the `#[cfg(feature = "sigstore-sign")]` branch around line 214, one in the `#[cfg(not(feature = "sigstore-sign"))]` branch around line 251) of:

```rust
            None => match check_trusted_publishing(
                &client,
                &prefix_data.url,
                &TrustedPublishingOptions::for_prefix_dev(),
            )
```

Replace the options expression in BOTH with:

```rust
            None => match check_trusted_publishing(
                &client,
                &prefix_data.url,
                &TrustedPublishingOptions::for_host(&prefix_data.url)
                    .unwrap_or_else(TrustedPublishingOptions::for_prefix_dev),
            )
```

(`prefix_data.url` always has a host in practice — it's an `https` server URL with default `https://prefix.dev` — the fallback just keeps the expression total.)

- [ ] **Step 2: Verify both cfg branches compile and tests pass**

Run: `pixi run -- cargo check -p rattler_upload` (default features)
Run: `pixi run -- cargo check -p rattler_upload --no-default-features` (covers the other cfg branch if `sigstore-sign` is a default feature — check `crates/rattler_upload/Cargo.toml` `[features]` and use whichever flag combination toggles `sigstore-sign` both on and off)
Run: `pixi run -- cargo nextest run -p rattler_upload`
Expected: clean compiles, all tests pass (22).
Run: `cargo clippy -p rattler_upload --all-targets -- -D warnings` → clean.

- [ ] **Step 3: Commit**

```bash
pixi run -- cargo fmt -p rattler_upload
git add crates/rattler_upload/src/upload/prefix.rs
git commit -m "feat(upload): derive trusted publishing audience from the upload host"
```

---

### Task 3: channel-aware middleware wiring in `rattler-bin`

**Files:**
- Modify: `crates/rattler-bin/src/commands/client.rs`
- Modify: `crates/rattler-bin/src/commands/create.rs:182`

- [ ] **Step 1: Write the failing test for the host policy**

Append to `crates/rattler-bin/src/commands/client.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_dev_host_policy() {
        assert!(is_prefix_dev_host("prefix.dev"));
        assert!(is_prefix_dev_host("beta.prefix.dev"));
        assert!(is_prefix_dev_host("staging.beta.prefix.dev"));
        // not subdomains of prefix.dev:
        assert!(!is_prefix_dev_host("evil-prefix.dev"));
        assert!(!is_prefix_dev_host("prefix.dev.evil.com"));
        assert!(!is_prefix_dev_host("conda.anaconda.org"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pixi run -- cargo nextest run -p rattler-bin prefix_dev_host_policy`
Expected: compile error — `is_prefix_dev_host` not found.

- [ ] **Step 3: Implement the policy and the channel-aware constructor**

Rewrite `crates/rattler-bin/src/commands/client.rs` as:

```rust
use std::{collections::HashMap, sync::Arc};

use miette::{Context, IntoDiagnostic};
use rattler_conda_types::Channel;
use rattler_networking::{
    AuthChallengeMiddleware, AuthenticationMiddleware, AuthenticationStorage,
    trusted_publishing::{TrustedPublishingFlow, TrustedPublishingOptions},
};
use reqwest::Client;
use url::Url;

pub const USER_AGENT: &str = concat!("rattler/", env!("CARGO_PKG_VERSION"));

/// Hosts for which the CLI is willing to perform CI OIDC trusted publishing.
/// Restricting this keeps the CLI from volunteering CI identity tokens to
/// arbitrary channel hosts.
fn is_prefix_dev_host(host: &str) -> bool {
    host == "prefix.dev" || host.ends_with(".prefix.dev")
}

/// Creates an HTTP client with the middleware stack used by the CLI for remote fetches.
pub fn create_client_with_middleware() -> miette::Result<reqwest_middleware::ClientWithMiddleware> {
    create_client_with_middleware_for_channels(&[])
}

/// Like [`create_client_with_middleware`], but additionally layers one
/// [`AuthChallengeMiddleware`] per unique `https` channel host that matches
/// the prefix.dev host policy. On a `WWW-Authenticate` challenge from such a
/// host, the middleware acquires a token via CI OIDC trusted publishing
/// (audience = the channel host) and replays the request.
///
/// This is the reference wiring for challenge-reactive private-channel
/// reads (see prefix-dev/pixi#6318).
pub fn create_client_with_middleware_for_channels(
    channels: &[Channel],
) -> miette::Result<reqwest_middleware::ClientWithMiddleware> {
    let download_client = Client::builder()
        .no_gzip()
        .user_agent(USER_AGENT)
        .build()
        .into_diagnostic()
        .context("failed to create HTTP client")?;

    let authentication_storage =
        AuthenticationStorage::from_env_and_defaults().into_diagnostic()?;

    let mut client = reqwest_middleware::ClientBuilder::new(download_client.clone())
        .with_arc(Arc::new(AuthenticationMiddleware::from_auth_storage(
            authentication_storage.clone(),
        )));

    // The mint exchange must not itself go through AuthChallengeMiddleware
    // (it would recurse), so it uses a plain client.
    let mint_client = reqwest_middleware::ClientBuilder::new(download_client.clone()).build();

    let mut seen_hosts = std::collections::HashSet::new();
    for channel in channels {
        let url: &Url = channel.base_url.as_ref();
        let (Some(host), "https") = (url.host_str(), url.scheme()) else {
            continue;
        };
        if !is_prefix_dev_host(host) || !seen_hosts.insert(host.to_string()) {
            continue;
        }
        let Some(options) = TrustedPublishingOptions::for_host(url) else {
            continue;
        };
        let mut server = url.clone();
        server.set_path("/");
        server.set_query(None);
        client = client.with_arc(Arc::new(AuthChallengeMiddleware::new(
            server,
            Arc::new(TrustedPublishingFlow::new(options, mint_client.clone())),
        )));
    }

    let client = client.with(rattler_networking::OciMiddleware::new(download_client));
    #[cfg(feature = "s3")]
    let client = client.with(rattler_networking::S3Middleware::new(
        HashMap::new(),
        authentication_storage,
    ));
    #[cfg(feature = "gcs")]
    let client = client.with(rattler_networking::GCSMiddleware::default());

    Ok(client.build())
}
```

Notes for the implementer:
- The `let (Some(host), "https") = ... else` destructuring form may not parse as written (tuple of pattern + literal in let-else); if the compiler rejects it, use the plain form:
  ```rust
  if url.scheme() != "https" {
      continue;
  }
  let Some(host) = url.host_str() else {
      continue;
  };
  ```
- `#[cfg(not(any(feature = "s3")))]` unused-variable warnings on `authentication_storage`: if clippy complains when `s3` is off, add `let _ = &authentication_storage;` — check with both feature sets.
- Imports may need adjusting to what `lib rattler_networking` actually re-exports: `AuthChallengeMiddleware` is at the crate root; `TrustedPublishingFlow`/`TrustedPublishingOptions` are in `rattler_networking::trusted_publishing`.

- [ ] **Step 4: Switch the `create` command to the channel-aware constructor**

In `crates/rattler-bin/src/commands/create.rs:182`, change:

```rust
    let download_client = super::client::create_client_with_middleware()?;
```

to:

```rust
    let download_client = super::client::create_client_with_middleware_for_channels(&channels)?;
```

(`channels: Vec<Channel>` is already in scope from line ~166.)

- [ ] **Step 5: Run tests and lints**

Run: `pixi run -- cargo nextest run -p rattler-bin prefix_dev_host_policy`
Expected: PASS.
Run: `pixi run -- cargo check -p rattler-bin` and `cargo clippy -p rattler-bin --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
pixi run -- cargo fmt -p rattler-bin
git add crates/rattler-bin/src/commands/client.rs crates/rattler-bin/src/commands/create.rs
git commit -m "feat(rattler-bin): wire AuthChallengeMiddleware for prefix.dev channel hosts"
```

---

### Task 4: e2e script + pixi feature/environment

**Files:**
- Create: `scripts/e2e/prefix-dev-oidc.nu`
- Modify: `pixi.toml` (after the S3 e2e block at ~line 115)
- Modify: `pixi.lock` (regenerated — intentional)

- [ ] **Step 1: Write the script**

Create `scripts/e2e/prefix-dev-oidc.nu`:

```nu
#!/usr/bin/env nu
# End-to-end test of the prefix.dev OIDC flow (see
# docs/superpowers/specs/2026-06-11-prefix-dev-oidc-e2e-design.md).
#
# Steps are ordered so the first failure names the broken component:
#   1. independent mint            -> repository-access config / mint endpoint
#   2. best-effort cleanup         -> (tolerant)
#   3. upload (proactive OIDC)     -> rattler_upload audience / write scope
#   4. anonymous challenge check   -> server WWW-Authenticate behavior
#   5. challenge-reactive read     -> AuthChallengeMiddleware / TrustedPublishingFlow

let host = ($env.PREFIX_DEV_E2E_HOST? | default "https://beta.prefix.dev")
let channel = ($env.PREFIX_DEV_E2E_CHANNEL? | default "rattler-e2e")
let package_file = "test-data/packages/empty-0.1.0-h4616a5c_0.conda"
let package_filename = "empty-0.1.0-h4616a5c_0.conda"
let audience = ($host | url parse | get host)

def fail [msg: string] {
  print $"FAIL: ($msg)"
  exit 1
}

# Run an external command; hard-fail with `indicts` if it exits non-zero.
def must [desc: string, indicts: string, cmd: closure] {
  print $"== ($desc)"
  try { do $cmd } catch { }
  let code = ($env.LAST_EXIT_CODE? | default 0)
  if $code != 0 {
    fail $"($desc) failed \(exit=($code)\) — ($indicts)"
  }
}

# -- Step 0: preconditions ---------------------------------------------------
if ($env.RATTLER_AUTH_FILE? | default "" | is-not-empty) {
  fail "RATTLER_AUTH_FILE is set; this test must run without stored credentials"
}
if ($env.ACTIONS_ID_TOKEN_REQUEST_URL? | default "" | is-empty) {
  fail "ACTIONS_ID_TOKEN_REQUEST_URL missing; the job needs `permissions: id-token: write`"
}

# -- Step 1: independent mint (proves server half without any rattler code) --
print $"== Step 1: independent OIDC mint against ($host) \(audience ($audience)\)"
let oidc_token = (
  try {
    http get --headers [Authorization $"bearer ($env.ACTIONS_ID_TOKEN_REQUEST_TOKEN)"] $"($env.ACTIONS_ID_TOKEN_REQUEST_URL)&audience=($audience)"
      | get value
  } catch {
    fail "could not fetch the GitHub Actions OIDC token — runner/permissions problem"
  }
)
let minted = (
  try {
    http post --content-type application/json $"($host)/api/oidc/mint_token" { token: $oidc_token }
  } catch {
    fail $"mint endpoint ($host)/api/oidc/mint_token rejected the OIDC token — check the repository-access config \(repo + audience ($audience)\) on the server"
  }
)
if not ($minted | into string | str starts-with "pfx-jwt") {
  fail $"mint endpoint returned something that is not a pfx-jwt token"
}
print "   minted a short-lived token: server mint + repository access OK"

# -- Step 2: best-effort cleanup of a previous run's package ------------------
print "== Step 2: best-effort cleanup of previous package"
try {
  http delete --headers [Authorization $"Bearer ($minted)"] $"($host)/api/v1/delete/($channel)/noarch/($package_filename)"
  print "   deleted previous package"
} catch {
  print "   nothing to delete (or delete refused) — continuing; upload uses --skip-existing"
}

# -- Step 3: upload through the proactive trusted-publishing path -------------
must $"Step 3: rattler upload prefix to ($host)/($channel)" "proactive OIDC upload path (rattler_upload audience or write scope)" {
  ^rattler upload prefix --url $host --channel $channel --skip-existing $package_file
}

# -- Step 4: the server must fire the challenge for anonymous access ----------
print "== Step 4: anonymous request must be challenged with WWW-Authenticate"
let resp = (http get --full --allow-errors $"($host)/($channel)/noarch/repodata.json")
if not ($resp.status in [401 403]) {
  fail $"expected 401/403 for anonymous access, got ($resp.status) — is the channel private?"
}
let www = ($resp.headers.response | where name == "www-authenticate")
if ($www | is-empty) {
  fail $"got ($resp.status) but no WWW-Authenticate header — the server does not fire the challenge"
}
let www_value = ($www | first | get value)
if not ($www_value | str downcase | str contains "bearer") {
  fail $"WWW-Authenticate present but without a Bearer scheme: ($www_value)"
}
print $"   challenged with: ($www_value)"

# -- Step 5: the actual challenge-reactive read through the rattler CLI -------
must $"Step 5: rattler create --dry-run from ($host)/($channel)" "challenge-reactive read path (AuthChallengeMiddleware / TrustedPublishingFlow)" {
  ^rattler create --dry-run -c $"($host)/($channel)" "empty==0.1.0"
}

print "== SUCCESS: full OIDC circle (independent mint, upload, challenge, reactive read) passed"
```

Implementer notes:
- nushell 0.106 `http get --full` returns a record with `status` and `headers` (with `request`/`response` tables of `name`/`value` rows). If the shape differs in the pinned version, run `nu -c 'http get --full --allow-errors https://example.com | describe'` inside the pixi env and adapt the two header lookups — keep the assertions identical in meaning.
- The minted token stays in a variable; never `print` it.

- [ ] **Step 2: Add the pixi feature, task, and environment**

In `pixi.toml`, after the S3 e2e block (after the `[environments.s3]` entry):

```toml
#------------------------------
# prefix.dev OIDC E2E test
#------------------------------
[feature.prefix-dev-e2e.dependencies]
rattler = { path = "crates/rattler-bin" }
nushell = ">=0.106.1,<0.107"

[feature.prefix-dev-e2e.tasks]
e2e-prefix-dev = "nu scripts/e2e/prefix-dev-oidc.nu"

[environments.prefix-dev-e2e]
features = ["prefix-dev-e2e"]
no-default-feature = true
```

- [ ] **Step 3: Regenerate the lockfile and smoke-run the script locally**

Run: `pixi lock` (or `pixi install -e prefix-dev-e2e`) — this updates `pixi.lock`; that change IS part of this commit.
Run: `pixi run -e prefix-dev-e2e -- nu --commands "source scripts/e2e/prefix-dev-oidc.nu" 2>&1 | head -5` — outside CI this must fail fast at Step 0 with the `ACTIONS_ID_TOKEN_REQUEST_URL missing` message (that failure IS the expected local result and proves the script parses and the guard works). If nu reports a syntax error instead, fix the script.

- [ ] **Step 4: Commit**

```bash
git add scripts/e2e/prefix-dev-oidc.nu pixi.toml pixi.lock
git commit -m "test(e2e): add prefix.dev OIDC end-to-end script and pixi task"
```

---

### Task 5: GitHub Actions workflow

**Files:**
- Create: `.github/workflows/e2e-prefix-dev-tests.yml`

- [ ] **Step 1: Write the workflow**

Copy the pinned action SHAs from `.github/workflows/e2e-s3-tests.yml` (checkout and setup-pixi steps) verbatim. Create:

```yaml
on:
  push:
    branches: [main]
    paths:
      - crates/rattler-bin/**
      - crates/rattler_networking/**
      - crates/rattler_upload/**
      - scripts/e2e/prefix-dev-oidc.nu
      - pixi.toml
      - pixi.lock
      - .github/workflows/e2e-prefix-dev-tests.yml
  workflow_dispatch:

name: E2E prefix.dev OIDC Tests

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: false

env:
  RUST_LOG: rattler_networking=debug,info
  RUST_BACKTRACE: 1
  CARGO_TERM_COLOR: always

jobs:
  e2e-prefix-dev-oidc:
    name: E2E Upload/Challenged-Read [beta.prefix.dev]
    runs-on: ubuntu-latest
    # The OIDC identity is only authorized (via the server-side repository
    # access config) for this repository; manual dispatch allows bring-up
    # runs from a branch.
    if: github.ref == 'refs/heads/main' || github.event_name == 'workflow_dispatch'
    permissions:
      id-token: write
      contents: read

    env:
      # Enable sccache (picked up by pixi build).
      SCCACHE_GHA_ENABLED: "true"

    steps:
      - name: Checkout source code
        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with:
          submodules: recursive

      - uses: prefix-dev/setup-pixi@5185adfbffb4bd703da3010310260805d89ebb11 # v0.9.6
        with:
          environments: prefix-dev-e2e

      - run: pixi run -vv e2e-prefix-dev
```

(Before committing, diff the two pinned SHAs against the current `e2e-s3-tests.yml` in case that file was updated since this plan was written — always use the repo's current pins.)

- [ ] **Step 2: Validate the workflow file**

Run: `pixi exec --spec actionlint -- actionlint .github/workflows/e2e-prefix-dev-tests.yml` (or, if actionlint is unavailable, `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/e2e-prefix-dev-tests.yml'))"` for a YAML-validity check).
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/e2e-prefix-dev-tests.yml
git commit -m "ci: add prefix.dev OIDC e2e workflow"
```

---

### Task 6: full verification

**Files:** none new.

- [ ] **Step 1: Workspace lint + format**

Run: `pixi run cargo-fmt` → no diff.
Run: `pixi run cargo-clippy` → zero warnings (workspace, `-D warnings`; takes minutes).

- [ ] **Step 2: Test the touched crates**

Run: `pixi run -- cargo nextest run -p rattler_networking -p rattler_upload -p rattler-bin`
Expected: all pass (53 in rattler_networking incl. the 2 new `for_host` tests, 22 in rattler_upload, ≥1 in rattler-bin).

- [ ] **Step 3: Commit any fallout**

```bash
git add -A ':!pixi.lock'
git diff --cached --quiet || git commit -m "chore: fmt/clippy fallout for prefix.dev e2e"
```
(`pixi.lock` was already committed in Task 4; exclude any later incidental churn.)

---

## Bring-up (human steps — not for the executing agent)

1. On beta.prefix.dev: create the **private** channel `rattler-e2e`; configure repository access (provider GitHub, repository `nichmor/rattler` for bring-up and `conda/rattler` for production, scope **read-write-delete**, audience `beta.prefix.dev`). Verify anonymous `GET /rattler-e2e/noarch/repodata.json` answers 401/403 **with** `WWW-Authenticate: Bearer …`.
2. Push `auth-challenge-e2e` to the fork; run the workflow via **workflow_dispatch** from that branch; iterate until green (step numbers in the log name the failing component).
3. Confirm or correct the step-2 delete endpoint (`/api/v1/delete/{channel}/{subdir}/{filename}`) against beta's API; if different, fix the script (tolerant step — a wrong path only degrades cleanup).
4. After conda/rattler#2504 merges, rebase this branch onto main and open the follow-up PR; add `conda/rattler` to the server-side repository-access config before merging it.

## Spec coverage map

| Spec section | Task |
|---|---|
| §1 `for_host` constructor + unit tests + security note | 1 |
| §2 upload audience from host (both cfg branches) | 2 |
| §3 CLI channel-aware wiring, host policy, mint-client recursion caveat | 3 |
| §4 nu script (5 steps, diagnostics ordering, env config, token hygiene) | 4 |
| §5 workflow (triggers, gating, id-token, sccache, RUST_LOG) | 5 |
| §6 provisioning + bring-up procedure | Bring-up section (human) |
| Error-handling principles (hard/tolerant steps, log diagnosability) | 4 (script structure) |
| Testing-the-test (unit tests, composed coverage, dispatch bring-up) | 1, 3, Bring-up |

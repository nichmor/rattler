# prefix.dev OIDC End-to-End Test — Design

**Date:** 2026-06-11
**Branch:** `auth-challenge-e2e` (stacked on `auth-challenge-middleware`, PR conda/rattler#2504)
**Motivation:** Prove the challenge-reactive OIDC read path (pixi#6318 fix) end to end
against a real server — `beta.prefix.dev`, which sends `WWW-Authenticate` challenges
for anonymous access to private channels.

## Goals

1. A CI job that exercises the full chain: GitHub Actions OIDC identity →
   `WWW-Authenticate` challenge → `TrustedPublishingFlow` mint →
   `AuthChallengeMiddleware` replay → private-channel repodata read.
2. Reference wiring of `AuthChallengeMiddleware` in the `rattler` CLI — the
   same shape pixi will adopt.
3. Audience derivation from the server host, used consistently by the read
   (middleware) and write (`rattler upload prefix`) paths.
4. Failure diagnostics that name the broken component (server config, mint
   endpoint, header behavior, or client middleware) from the job log alone.

## Non-goals / out of scope

- pixi wiring (pixi repo).
- A GitLab CI mirror of the test (the GitLab detector is covered by unit
  tests via `temp-env`; the GitHub detector is covered by this job).
- Testing against production `prefix.dev`.
- Attestation generation during upload.

## Components

### 1. `rattler_networking`: `TrustedPublishingOptions::for_host`

```rust
impl TrustedPublishingOptions {
    /// Options for any trusted-publishing server following the prefix.dev
    /// convention: the OIDC audience is the server's host name and tokens
    /// are minted at `/api/oidc/mint_token`.
    ///
    /// Returns `None` when `server` has no host (e.g. `file://` URLs).
    pub fn for_host(server: &Url) -> Option<Self>;
}
```

`for_prefix_dev()` remains (it is `for_host` applied to `https://prefix.dev`).
Unit test: `for_host(https://beta.prefix.dev/some/channel)` →
audience `beta.prefix.dev`, mint path `/api/oidc/mint_token`; `for_host` of a
URL without host → `None`.

Security note: an OIDC ID token minted with `aud = <host>` is only redeemable
at that host; deriving the audience from the host therefore scopes each
credential to the server it is sent to.

### 2. `rattler_upload`: host-derived audience

Both `TrustedPublishingOptions::for_prefix_dev()` call sites in
`crates/rattler_upload/src/upload/prefix.rs` (the `sigstore-sign` and
non-`sigstore-sign` branches) become
`TrustedPublishingOptions::for_host(&prefix_data.url)`, falling back to
`for_prefix_dev()` when `for_host` returns `None`. Uploads to
`https://beta.prefix.dev` then request `aud=beta.prefix.dev` instead of the
currently hardcoded `aud=prefix.dev`.

### 3. `rattler-bin`: channel-aware middleware wiring (reference for pixi)

`crates/rattler-bin/src/commands/client.rs` gains a channel-aware constructor
(the existing zero-argument `create_client_with_middleware()` stays for call
sites without channel context):

```rust
pub fn create_client_with_middleware_for_channels(
    channels: &[Channel],
) -> miette::Result<ClientWithMiddleware>
```

For each unique `https` channel host where the host equals `prefix.dev` or
ends with `.prefix.dev`, it layers one
`AuthChallengeMiddleware::new(host_url, Arc::new(TrustedPublishingFlow::new(options, mint_client)))`
after `AuthenticationMiddleware`, where `options =
TrustedPublishingOptions::for_host(host_url)` and `mint_client` is a plain
reqwest-middleware client (no challenge middleware — the documented recursion
caveat). The `create` command passes its resolved channels.

The `.prefix.dev` suffix policy is deliberate: the CLI must not volunteer CI
identity tokens to arbitrary channel hosts. Hosts outside the policy simply
keep today's behavior. (Audience binding already limits the damage of a
mis-sent token; the policy removes the leak of workflow-identity claims.)

### 4. `scripts/e2e/prefix-dev-oidc.nu` + pixi task

A nushell script in the style of `scripts/e2e/s3-aws.nu`, registered as pixi
task `e2e-prefix-dev`. Configuration via env vars with defaults:
`PREFIX_DEV_E2E_HOST=https://beta.prefix.dev`,
`PREFIX_DEV_E2E_CHANNEL=rattler-e2e`. Test package:
`test-data/packages/empty-0.1.0-h4616a5c_0.conda` (noarch, already in repo).

Flow (each step prints what it proved or which component it indicts):

| # | Step | Indicts on failure | Hard fail? |
|---|------|--------------------|------------|
| 1 | Mint independently: fetch GitHub OIDC token from `$ACTIONS_ID_TOKEN_REQUEST_URL` with `audience=beta.prefix.dev`, POST to `/api/oidc/mint_token`, require a `pfx-jwt.*` token | repository-access config / mint endpoint | yes |
| 2 | Best-effort cleanup: `DELETE /api/v1/delete/<channel>/noarch/empty-0.1.0-h4616a5c_0.conda` with the step-1 Bearer token; ignore failure | — (tolerant) | no |
| 3 | Upload: `rattler upload prefix --url <host> --channel <channel> --skip-existing <pkg>` with no stored credentials | proactive OIDC upload path (`rattler_upload` audience) | yes |
| 4 | Header check: anonymous `curl -sI <host>/<channel>/noarch/repodata.json` must return 401 or 403 **with** a `WWW-Authenticate` header containing `Bearer` | server challenge behavior (the premise of the whole design) | yes |
| 5 | Challenge-reactive read: `rattler create --dry-run -c <host>/<channel> empty==0.1.0` with `RATTLER_AUTH_FILE` unset and no keyring state | client middleware (challenge → mint → replay) | yes |

`RUST_LOG=rattler_networking=debug` so the middleware's challenge/mint
tracing lands in the job log. Step 1's token is held in a script variable
only, never written to disk or echoed.

The step-2 delete endpoint path (`/api/v1/delete/{channel}/{subdir}/{filename}`)
is to be confirmed against beta.prefix.dev's API during implementation; the
step is tolerant, so a wrong path degrades to `--skip-existing` uploads
(read test unaffected).

### 5. `.github/workflows/e2e-prefix-dev-tests.yml`

Modeled on `e2e-s3-tests.yml`:

- Triggers: `push` to `main` with paths
  (`crates/rattler-bin/**`, `crates/rattler_networking/**`,
  `crates/rattler_upload/**`, `scripts/e2e/prefix-dev-oidc.nu`, `pixi.toml`,
  `pixi.lock`, the workflow file) and `workflow_dispatch` (for manual runs
  from a branch during bring-up).
- Job `e2e-prefix-dev-oidc`: `runs-on: ubuntu-latest`,
  `permissions: { id-token: write, contents: read }`,
  `if: github.ref == 'refs/heads/main' || github.event_name == 'workflow_dispatch'`,
  checkout → setup-pixi → `pixi run -vv e2e-prefix-dev`. sccache enabled like
  the S3 job.

### 6. One-time manual provisioning on beta.prefix.dev (human task)

- Create a **private** channel `rattler-e2e`.
- Configure repository access: provider GitHub, repository `conda/rattler`
  (plus the development fork `nichmor/rattler` during bring-up), scope
  **read-write-delete**, audience `beta.prefix.dev`.
- Verify the server sends `WWW-Authenticate: Bearer ...` on anonymous access
  to the private channel (step 4 of the script asserts this every run).

## Error-handling principles

- Steps 1, 3, 4, 5 hard-fail the job; step 2 is tolerant.
- Diagnostic ordering is the design: a failure earlier in the sequence
  invalidates later steps, so the first red step names the broken component.
- A red job must be diagnosable from the log alone: each step echoes its
  purpose, target URL, and observed status (never the token).

## Testing the test

- `for_host`: unit tests in `rattler_networking`.
- CLI wiring: one integration-style unit test in `rattler-bin` is impractical
  (network); instead the wiring function is kept small and the composed
  middleware behavior is already covered by
  `middleware_with_trusted_publishing_flow_end_to_end` in
  `rattler_networking`. The CI job itself is the integration test.
- Bring-up procedure: run the workflow via `workflow_dispatch` from the
  `auth-challenge-e2e` branch on the fork (with the fork added to the
  repository-access config) before merging.

## Decisions log

| Decision | Choice | Why |
|---|---|---|
| Harness | Wire the `rattler` CLI + nu script | Matches existing `e2e-s3` pattern; doubles as pixi reference wiring |
| CI platform | GitHub Actions | rattler's home; `id-token: write` covers the GitHub `ambient-id` detector |
| Audience | Derived from server host (`for_host`) | Works for beta + prod without hardcoding; audience-binds each credential to its server |
| Channel scope policy in CLI | `prefix.dev` / `*.prefix.dev` only | Don't volunteer CI identity tokens to arbitrary channel hosts |
| Provisioning | Full circle: best-effort delete → upload → read each run | Tests both OIDC halves (proactive upload, reactive read) every run |
| Branch/PR | `auth-challenge-e2e` stacked on #2504, follow-up PR | Keeps the middleware PR focused; e2e can't merge first anyway |

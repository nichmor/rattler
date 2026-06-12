# How the prefix.dev OIDC auth flow was tested

**Date:** 2026-06-12
**Branches:** `auth-challenge-middleware` (conda/rattler#2504) + `auth-challenge-e2e` (stacked)
**Goal:** prove the fix for [pixi#6318](https://github.com/prefix-dev/pixi/issues/6318) — reading
private prefix.dev channels in CI via OIDC "repository access", with zero stored secrets.

The flow under test, end to end:

```
GitHub Actions OIDC identity
  → anonymous request to a private channel is answered with 401 + WWW-Authenticate
  → AuthChallengeMiddleware asks TrustedPublishingFlow for a token
  → ambient-id fetches the CI OIDC token (aud=prefix.dev)
  → POST /api/oidc/mint_token exchanges it for a short-lived pfx-jwt bearer token
  → the request is replayed once with Authorization: Bearer
  → repodata/package downloads succeed; the token is cached for subsequent requests
```

Testing happened in three layers, each catching what the previous one can't.

---

## Layer 1 — unit & integration tests (no network, run on every CI build)

All in `crates/rattler_networking` (`pixi run -- cargo nextest run -p rattler_networking`):

- **`WWW-Authenticate` parser** (10 tests): single/multiple challenges, multiple headers,
  quoted commas, token68 blobs (incl. `==` padding), unbalanced quotes, space-separated
  params, garbage input. Contract: malformed input yields *fewer* params, never wrong
  values, never a panic.
- **Token cache** (4 tests): JWT `exp` extraction, 60-second refresh margin, opaque tokens
  cached without expiry, header-value validation *before* caching (a malformed token
  disables the flow instead of poisoning the host).
- **`AuthChallengeMiddleware` behavior** (10 tests, axum loopback servers + mock `AuthFlow`):
  challenge → mint → replay-once; cached-token reuse (zero extra round trips); negative
  caching (`Ok(None)`/errors consulted exactly once); host/scheme/port scoping;
  `Authorization`-header precedence; stale-token clear-and-reacquire (asserted via the
  full header sequence the server observed, so a non-caching impostor fails the test);
  flow errors surface the server's original 401, never a middleware error.
- **`TrustedPublishingFlow`** (audience/mint tests): GitLab detector exercised for real via
  `temp-env` (`GITLAB_CI` + `PREFIX_DEV_ID_TOKEN`, other providers unset) against a mock
  mint endpoint; Bearer-only challenge filtering; `for_host`/`for_server` audience rules
  (prefix.dev family shares `prefix.dev`; lookalike hosts like `evil-prefix.dev` excluded).
- **Composed end-to-end (in-process)**: one axum server hosting both a challenging
  channel route and a mint endpoint; real `AuthChallengeMiddleware` + real
  `TrustedPublishingFlow` + fake GitLab env. Asserts challenge → detect → mint → replay →
  200, and that the second request reuses the cache (mint endpoint hit exactly once).

Plus `rattler_upload` (22 tests, unchanged behavior) and the `rattler-bin` host-policy
test (`prefix.dev` family allow-list, fail-closed on `evil-prefix.dev`,
`prefix.dev.evil.com`, trailing-dot hosts).

## Layer 2 — harness verification (the test of the test)

- The e2e nu script was smoke-run locally: parses under the pinned nushell 0.106.1,
  Step-0 guards fire correctly (`RATTLER_AUTH_FILE`/`NETRC`/credentials-file/OIDC env).
- Token hygiene verified empirically: every failure path was forced and the output
  inspected — no path echoes the OIDC or minted token (nu `catch` suppresses bodies;
  error bodies are printed truncated only for the mint step, where they are server
  diagnostics, not credentials).
- The `must` helper (exit-code capture) was tested for false-success paths, including
  missing binaries.
- Workflow validated with `actionlint`; OIDC exposure reviewed: `id-token: write` only,
  no `pull_request` trigger, so fork PRs can never mint.

## Layer 3 — live end-to-end against beta.prefix.dev (GitHub Actions)

The CI script (`scripts/e2e/prefix-dev-oidc.nu`) runs five steps ordered so that **the
first failing step names the broken component**:

| # | Step | Failure indicts |
|---|------|-----------------|
| 1 | Independent mint: fetch the runner's OIDC token, POST to `/api/oidc/mint_token` | repository-access config / mint endpoint |
| 2 | Best-effort delete of the previous test package (tolerant) | — |
| 2b | Authenticated read probe with the minted token | token↔channel attachment vs. scope |
| 3 | `rattler upload prefix` (proactive OIDC path) | upload path / write scope |
| 4 | Anonymous GET must return 401/403 **with** `WWW-Authenticate: Bearer` (both `repodata.json` and the sharded index) | server challenge behavior |
| 5 | `rattler create --dry-run` with no stored credentials | the challenge-reactive middleware itself |

### Run-by-run findings (the bring-up log)

| Run | Change | Result | Conclusion |
|-----|--------|--------|------------|
| 1 | initial | Step 1 fail (opaque) | mint rejected; diagnostics insufficient |
| 2 | surface mint error bodies | `InvalidAudience` for `aud=beta.prefix.dev` | beta validates GitHub OIDC against a **fixed** audience, before consulting any config |
| 3 | re-run after server config added | same `InvalidAudience` | confirmed: audience check is code, not config |
| 4 | client amended: prefix.dev-family hosts share audience `prefix.dev` (`TrustedPublishingOptions::for_server`) | Steps 1–2 ✓; Step 3 upload **403** | mint + repository access work; write denied |
| 5 | repository-access scope switched to read-write | Step 3 still 403 | scope flip not sufficient |
| 6 | added Step 2b read probe | **read probe 200**; upload still 403 | the minted token *is* attached to the channel and can read; `/api/v1/upload` denies it — server-side write authorization for pfx-jwt tokens (under investigation on beta) |
| — | manual anonymous probe from a dev machine | `HTTP/2 401` + `www-authenticate: Bearer realm="beta.prefix.dev"` | **the server fires the challenge** — the premise of the whole design holds on beta |
| 7 | `skip_upload` dispatch input; Step 5 classifies "no candidates" as auth-success | Steps 1, 4 ✓; Step 5 **AUTH PATH VERIFIED**; run green | **the challenge-reactive read works end to end on real infrastructure** — the pixi#6318 fix is demonstrated; only the upload half remains blocked |

### Scoreboard

| Link in the chain | Status |
|---|---|
| GitHub OIDC token issued in CI | ✓ proven (runs 4–6) |
| Beta mints `pfx-jwt` (audience `prefix.dev`) | ✓ proven (runs 4–6, twice per run) |
| Minted token reads the private channel | ✓ proven (run 6, status 200) |
| Beta challenges anonymous reads with `WWW-Authenticate: Bearer` | ✓ proven (manual probe) |
| OIDC **upload** via trusted publishing | ✗ blocked — beta returns 403 on `/api/v1/upload` for a token that can read (server-side investigation) |
| Challenge-reactive read through `rattler create` (Step 5 — the pixi#6318 fix) | **✓ proven live** (run 7, `skip_upload` dispatch): with zero stored credentials and anonymous access rejected, `rattler create` fetched the private repodata via challenge → mint → replay; the solve failed only with "no candidates" (test package not yet in the channel), which itself confirms the authenticated download succeeded |

### Design finding worth keeping

The original spec derived the OIDC audience from the server host
(`beta.prefix.dev` → `aud=beta.prefix.dev`) to audience-bind each credential to one
deployment. Live testing showed the deployed prefix.dev convention is a **single shared
audience `prefix.dev`** validated at JWT-decode time. The client now follows the deployed
convention for the prefix.dev family (`TrustedPublishingOptions::for_server`) and keeps
host-derived audiences for self-hosted servers; the spec's decisions log records the
amendment and the trade-off.

## Next steps

1. Beta-side: investigate the 403 from `/api/v1/upload/rattler-e2e` for minted pfx-jwt
   tokens that hold read access (scope claim vs. upload endpoint authorization).
2. Either fix the upload path, or temporarily upload the test package manually and gate
   Step 3 behind `PREFIX_DEV_E2E_SKIP_UPLOAD` to get the Step 4/5 verdict (the read path
   is the pixi#6318 fix; upload coverage can follow).
3. Once green: rebase onto main after conda/rattler#2504 merges, open the follow-up PR,
   add `conda/rattler` to the beta repository-access entry.

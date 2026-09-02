# Fork Changes

This is a security-hardened, maintained fork of
[strangelove-ventures/horcrux](https://github.com/strangelove-ventures/horcrux),
based on `v3.3.2` (the "single lock for read and write" release). The upstream
repository is archived. This fork adds two optional connection-security features,
a round of security hardening from two independent audits, dependency/toolchain
updates, and compatibility fixes for stricter priv-validator implementations.

Everything is **opt-in and backward-compatible**: with no new config, behavior is
identical to upstream `v3.3.2`.

The hardening items below are described at the level operators need to assess and
prioritize an upgrade. Precise exploitation details are intentionally omitted:
upstream is archived and cannot ship a patch, so other deployments may still be
affected — the responsible summary here is meant to help operators migrate, not to
arm attackers.

## Baseline verification

- `go build ./...`, `go vet ./...`, `gofmt` — clean.
- `go test ./signer/... ./cmd/...` — green (including the vendored crypto's own
  upstream test vectors and full sign/combine/verify).
- `govulncheck ./...` — **0 reachable vulnerabilities** (was 13 on the baseline).
- The double-sign concurrency test passes under `-race`.

## Summary of changes

Severity reflects impact on a threshold-mode validator (key compromise >
equivocation/slashing > liveness/DoS > hygiene).

| #   | Change                                                                  | Severity     | Kind                            |
| --- | ----------------------------------------------------------------------- | ------------ | ------------------------------- |
| 1   | Close an ed25519 nonce-handling flaw that risked key-material exposure  | **Critical** | Security fix                    |
| 2   | Prevent a concurrent cosigner double-sign at the same height/round/step | **Critical** | Security fix (defense-in-depth) |
| 3   | Remove an unauthenticated cluster admin/reflection surface              | **Critical** | Security fix                    |
| 4   | Harden RPC / priv-validator paths against crash-inducing input          | **High**     | Security fix                    |
| 5   | Reachable dependency CVEs → 0 (deps + Go toolchain bumps)               | **High**     | Public CVEs                     |
| 6   | Strict chain-ID validation (file paths + metric labels)                 | **Medium**   | Security fix                    |
| 7   | Peer-response validation + gRPC panic-recovery                          | **Medium**   | Security fix                    |
| 8   | Vendor threshold-ed25519 in-tree (drop archived GitLab deps)            | **Medium**   | Supply chain                    |
| 9   | Opt-in mutual TLS for the cosigner cluster transport                    | **Medium**   | Hardening (new)                 |
| 10  | Secrets-at-rest hygiene (dir perms, `.gitignore`)                       | **Low**      | Hardening                       |
| —   | Optional persistent priv-validator connection auth                      | n/a          | Feature                         |
| —   | Opt-in leader-only priv-validator connections (tm2/gno.land compat)     | n/a          | Feature                         |
| —   | Spec-compliant sign response for strict priv-validator nodes            | n/a          | Compatibility fix               |

---

## Details

### 1. ed25519 nonce-handling flaw → key-material exposure (Critical)

Per-signing nonces were not consumed once-and-only-once and a request could reuse a
nonce across the vote and its vote-extension. Reusing a nonce across two different
signed messages is the classic precondition for recovering ed25519 key material.
**Fix** (`signer/local_cosigner.go`): consume each nonce exactly once under a write
lock, require a threshold number of contributions, and reject a request that reuses
the same nonce for the vote and the vote-extension. Regression-tested across 2-of-3
and 3-of-5 with both cosigner security backends (RSA and ECIES).

### 2. Concurrent double-sign at the same HRS (Critical)

The v3.3.2 "single lock" fix made the leader's initiated-state gate atomic, but the
cosigner's own sign path could still, under specific timing, return a signature for
two different blocks at the same height/round/step. **Fix**
(`signer/local_cosigner.go`): on a same-HRS save conflict, re-validate the
just-signed payload against stored state and discard it if it differs. Verified
under the race detector.

### 3. Unauthenticated cluster admin surface (Critical)

The cosigner-to-cosigner gRPC server exposed an administrative surface (plus service
reflection) with no authentication, a remote liveness- and state-integrity risk on
the cluster port. **Fix** (`signer/raft_store.go`): removed it — horcrux has no
client that uses it.

### 4. Crash-inducing malformed input (High)

Several RPC and priv-validator code paths could be crashed by malformed input,
causing validator downtime, with no recovery installed. **Fix**: input validation at
the gRPC and priv-validator boundaries, guards on untrusted peer responses, and gRPC
panic-recovery interceptors (unary + stream) plus a recover backstop in the
priv-validator read loop, so malformed input drops a connection instead of the
process.

### 5. Dependency & Go toolchain CVEs (High)

`govulncheck` reported 13 reachable vulnerabilities across go-ethereum, gRPC,
CometBFT, cosmos-sdk, and golang.org/x packages, and the release image built on
**EOL Go 1.21**. **Fix**: bumped Go 1.21 → 1.25 (with a pinned patched-stdlib
toolchain floor) and cometbft `v0.38.2→v0.38.21`, cosmos-sdk `v0.50.1→v0.50.11`,
go-ethereum `v1.13.5→v1.17.5`, grpc `v1.59.0→v1.82.1`, protobuf, x/net, x/crypto,
x/sync, x/text, and others. Result: **govulncheck 0 reachable**.

### 6. Chain-ID input validation (Medium)

The chain ID (externally supplied over privval/gRPC) was used to build key/state
file paths and Prometheus metric labels without validation. **Fix**:
`ValidateChainID` (charset + length, rejects path separators) at every RPC handler
entry — before any file path or metric label — and in the single-signer and
threshold state loaders.

### 7. Peer-response validation & panic recovery (Medium)

Targets a misbehaving or on-path **peer cosigner** (the cluster transport is
plaintext unless mTLS, #9, is enabled): validate the length/shape of peer responses
before use, and unary + stream recovery interceptors so a peer cannot crash the
leader mid-sign.

### 8. Vendor threshold-ed25519 in-tree (Medium, supply chain)

The core threshold-signing math depended on `gitlab.com/unit410/threshold-ed25519`
and `gitlab.com/unit410/edwards25519` — untagged 2022 commits on an archived,
read-only GitLab group with no maintenance path. **Fix**: copied both packages
in-tree (`signer/tsed25519`, `signer/edwards25519`), verbatim, with licenses
preserved, and dropped the GitLab dependencies. Verbatim copy guarantees identical
behavior; the upstream test vectors run in-tree and pass.

### 9. Opt-in mutual TLS for the cosigner cluster transport (Medium)

The cosigner ↔ cosigner transport (raft + signing RPC) ran plaintext and
unauthenticated (a confidentiality / DoS / MITM concern). **Fix**: optional mutual
TLS with per-cosigner ed25519 self-signed certificates pinned by an allowlist of
peer public keys — no CA. Enabled by `clusterKeyFile` + per-cosigner `tlsPubKey`;
off by default. `horcrux create-cluster-key` generates the identity. See
[`authentication.md`](authentication.md).

### 10. Secrets-at-rest hygiene (Low)

Home/state directories created `0700` (was `0755`); `.gitignore` extended to cover
`ecies_keys.json`, `*_priv_validator_key.json`, `share.json`, and `cosigner_*/`.

### Feature: persistent priv-validator connection authentication

Optional `connKeyFile` gives the cosigner a stable ed25519 identity a chain node
can authorize, and per-node `connPubKey` lets the cosigner pin the node it connects
to. Both off by default. `horcrux create-conn-key` generates the key. See
[`authentication.md`](authentication.md).

### Feature: leader-only priv-validator connections (tm2/gno.land compat)

By default every cosigner dials every configured chain node, which only works when
the node's priv-validator listener tolerates the resulting connection contention.
CometBFT does; some stricter forks (e.g. gno.land / tm2) hold a single signer slot
and churn, so no signature is delivered. Optional
`thresholdMode.leaderOnlyChainNodeConnections: true` makes only the current raft
leader hold the priv-validator connections: followers park without dialing, and a
leader that loses its raft leadership releases the connection for its successor. Off
by default — the sharded-sentries topology (one cosigner per sentry) requires every
cosigner to dial its own sentries regardless of leadership. See
[`authentication.md`](authentication.md).

### Compatibility fix: spec-compliant sign response

The sign-response handlers returned an incomplete vote/proposal (only the signature
filled in). CometBFT's client tolerates that, but stricter priv-validator
implementations (e.g. gno.land / tm2) validate the returned message and reject it.
**Fix** (`signer/remote_signer.go`): echo the full request vote/proposal with only
the signer-owned fields (signature, timestamp, vote-extension signature) filled in —
matching CometBFT's own remote-signer response contract.

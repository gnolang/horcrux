# Hardened Horcrux — Fork Changes

This is a security-hardened fork of [strangelove-ventures/horcrux](https://github.com/strangelove-ventures/horcrux),
based on `v3.3.2` (the "single lock for read and write" release), plus an optional
priv-validator connection-authentication feature and a round of security hardening
driven by two full multi-agent security audits.

> **Keep this repository private until upstream has patched.** Several fixes below
> address previously-unknown vulnerabilities in upstream horcrux that affect every
> threshold-mode deployment. They are being reported to Strangelove through
> coordinated disclosure (private reports drafted under `.ignore/security-reports/`).
> Publishing the source-level fixes before upstream ships a patch would be a 0-day
> disclosure. The compiled Docker image is a much weaker disclosure surface, but
> this repository's history should not be made public until the upstream advisories
> are out.

## Baseline verification of the shipped artifact

- `go build ./...`, `go vet ./...`, `gofmt` — clean.
- `go test ./signer/... ./cmd/...` — green (including the vendored crypto's own
  upstream test vectors and full sign/combine/verify).
- `govulncheck ./...` — **0 reachable vulnerabilities** (was 13 on the baseline).
- The double-sign concurrency test passes under `-race`.

## Summary of changes

Severity reflects impact on a threshold-mode validator (key compromise > equivocation/slashing > liveness/DoS > hygiene).

| #   | Change                                                              | Severity     | Kind                                               | Reachable by                                                  |
| --- | ------------------------------------------------------------------- | ------------ | -------------------------------------------------- | ------------------------------------------------------------- |
| 1   | Prevent ed25519 nonce reuse → private key-shard extraction          | **Critical** | Novel upstream fix                                 | Anyone reaching a cosigner RPC port; a malicious/buggy leader |
| 2   | Prevent concurrent cosigner double-sign at the same HRS             | **Critical** | Novel upstream fix (defense-in-depth after v3.3.2) | Same as #1                                                    |
| 3   | Remove unauthenticated `raftadmin` (remote Shutdown / state-poison) | **Critical** | Novel upstream fix                                 | Anyone reaching the cosigner P2P port                         |
| 4   | Fix unauthenticated remote panics (process-kill DoS)                | **High**     | Novel upstream fix                                 | Anyone reaching a cosigner port; a chain node over privval    |
| 5   | Reachable dependency CVEs → 0 (deps + Go toolchain bumps)           | **High**     | Public CVEs                                        | Network peers / malicious input                               |
| 6   | Chain-ID path-traversal + metric-cardinality validation             | **Medium**   | Novel upstream fix                                 | Chain node over privval; cosigner RPC                         |
| 7   | Peer-response validation + gRPC panic-recovery (unary + stream)     | **Medium**   | Novel upstream fix                                 | Malicious/MITM peer cosigner                                  |
| 8   | Vendor threshold-ed25519 in-tree (drop archived GitLab deps)        | **Medium**   | Supply chain                                       | n/a (maintenance risk)                                        |
| 9   | Opt-in mutual TLS for the cosigner cluster transport                | **Medium**   | Hardening (new)                                    | n/a (closes confidentiality/DoS/MITM)                         |
| 10  | Secrets-at-rest hygiene (dir perms, `.gitignore`)                   | **Low**      | Hardening                                          | Local users                                                   |
| —   | Optional persistent priv-validator connection auth (feature)        | n/a          | Feature                                            | n/a                                                           |

Everything is **opt-in and backward-compatible**: with no new config, behavior is
identical to upstream v3.3.2.

---

## Details

### 1. Nonce reuse → private key-shard extraction (Critical)

**Problem.** A cosigner signed the vote and the vote-extension using nonces
selected by two request-supplied UUIDs, without checking they differ, and
`combinedNonces` neither consumed the nonce on read nor required a threshold
number of contributions. Sending one `SetNoncesAndSign` with equal UUIDs (or two
concurrent same-UUID requests) produced two Schnorr partial signatures over
different messages under the same nonce `R`, from which the cosigner's ed25519
private key shard is recovered algebraically (`x = (s1−s2)/(h1−h2)`). Recovering
`threshold` shards reconstructs the full validator key — permanent, unbounded
double-signing. Demonstrated end-to-end with a PoC that recovered the exact shard.

**Fix** (`signer/local_cosigner.go`):

- Reject `SetNoncesAndSign` when the vote and vote-extension UUIDs are equal.
- `combinedNonces` takes the write lock, deletes the nonce on read (consume-once),
  and errors if fewer than `threshold` contributions are present.

Regression-tested: equal-UUID rejected, sub-threshold rejected, and full
sign/combine/verify still passes (2-of-3, 3-of-5, RSA and ECIES).

### 2. Concurrent cosigner double-sign at the same HRS (Critical)

**Problem.** The v3.3.2 "single lock" fix made the _leader's_ initiated-state gate
atomic, but the _cosigner's_ own sign path was not: its pre-check took a read lock
and released it before signing, and a same-HRS `Save` conflict returned
`SameHRSError`, which the caller swallowed unconditionally — returning the
signature. Two concurrent requests for the same HRS with different blocks could
therefore each get a signature. Reproduced concurrently (defense-in-depth after
the upstream leader-side fix; reachable via a malicious/buggy leader or the
unauthenticated cosigner RPC).

**Fix** (`signer/local_cosigner.go`): on a same-HRS `Save` conflict, re-validate
the just-signed payload against the stored block; if it differs materially, return
an error and discard the signature. Verified under `-race` (40 concurrent rounds).
(An initial lock-based approach was dropped because it added latency during raft
leader churn; the payload re-check prevents the double-sign without serialization.)

### 3. Unauthenticated `raftadmin` control plane (Critical)

**Problem.** The cosigner P2P gRPC server registered `raftadmin` with no auth,
exposing remote `Shutdown` (instant liveness kill) and `ApplyLog` (inject an
arbitrary FSM command → permanently poison the on-disk double-sign watermark
cluster-wide). gRPC reflection made the surface self-describing.

**Fix** (`signer/raft_store.go`): removed `raftadmin.Register` (horcrux has no
client that uses it) and `reflection.Register` from both gRPC servers.

### 4. Unauthenticated remote panics (High)

**Problem.** Several code paths reachable from unvalidated protobuf input panicked
the process (validator downtime), with no gRPC recovery installed: nil `Block`,
zero-length UUID → `[16]byte` conversion (request _and_ peer-response paths), nil
`Hrst`, unchecked `int32→int8` step reaching `panic("unexpected sign step")`, and
nil-vote / unknown-vote-type on the privval connection.

**Fix**: explicit input validation at the gRPC and privval handler boundaries; a
length guard on peer-response UUIDs (which run in goroutines with no recovery in
scope); a short-partial-signature guard in `CombineSignatures`; and gRPC
panic-recovery interceptors (unary and stream) plus a recover backstop in the
privval read loop.

### 5. Dependency & Go toolchain CVEs (High)

**Problem.** `govulncheck` reported 13 reachable vulnerabilities, including a
go-ethereum ECIES flaw on the cosigner nonce-encryption path, a gRPC
authorization-bypass and HTTP/2 DoS on the listener, and CometBFT / cosmos-sdk /
x-net issues. The release image also built on **EOL Go 1.21**.

**Fix**: bumped Go 1.21 → 1.25 (go.mod, go.work, Dockerfile) and cometbft
`v0.38.2→v0.38.21`, cosmos-sdk `v0.50.1→v0.50.11`, go-ethereum `v1.13.5→v1.17.0`,
grpc `v1.59.0→v1.82.1`, protobuf, x/net, x/crypto, x/text, cosmossdk.io/math,
edwards25519, and others. Result: **govulncheck 0 reachable**.

### 6. Chain-ID path traversal & metric cardinality (Medium)

**Problem.** The chain ID (attacker-controlled over privval/gRPC) was used to
build key/state file paths and Prometheus metric labels without validation — a
path-traversal vector (notably in single-signer mode) and an unbounded
metric-label memory-DoS.

**Fix**: `ValidateChainID` (charset + length, rejects path separators / `..`)
called at every RPC handler entry — before any file path or metric label — and in
the single-signer and threshold state loaders.

### 7. Peer-response validation & panic recovery (Medium)

Covered operationally under #4; called out separately because it targets a
malicious or on-path _peer cosigner_ (the cluster transport is plaintext by
default): response UUID/length validation before use, and stream + unary recovery
interceptors so a peer cannot crash the leader mid-sign.

### 8. Vendor threshold-ed25519 in-tree (Medium, supply chain)

**Problem.** The core threshold-signing math depended on
`gitlab.com/unit410/threshold-ed25519` and `gitlab.com/unit410/edwards25519` —
untagged 2022 commits on an **archived, read-only** GitLab group with no
maintenance path.

**Fix**: copied both packages in-tree (`signer/tsed25519`, `signer/edwards25519`),
verbatim, with licenses preserved, and dropped the GitLab dependencies. Verbatim
copy guarantees identical behavior (no re-sharding, no protocol change); the
upstream test vectors run in-tree and pass.

### 9. Opt-in mutual TLS for the cosigner cluster transport (Medium)

**Problem.** The cosigner ↔ cosigner transport (raft + signing RPC) ran plaintext
and unauthenticated. (Key extraction over it is already blocked by #1–#3, so this
is a confidentiality / DoS / MITM concern rather than key theft.)

**Fix**: optional mutual TLS with per-cosigner ed25519 self-signed certificates
pinned by an allowlist of peer public keys — no CA. Enabled by `clusterKeyFile` +
per-cosigner `tlsPubKey`; off by default. `horcrux create-cluster-key` generates
the identity. See [`authentication.md`](authentication.md).

### 10. Secrets-at-rest hygiene (Low)

Home/state directories created `0700` (was `0755`); `.gitignore` extended to cover
`ecies_keys.json`, `*_priv_validator_key.json`, `share.json`, and `cosigner_*/`.

### Feature: persistent priv-validator connection authentication

Optional `connKeyFile` gives the cosigner a stable ed25519 identity a chain node
can authorize, and per-node `connPubKey` lets the cosigner pin the node it
connects to. Both off by default. `horcrux create-conn-key` generates the key. See
[`authentication.md`](authentication.md).

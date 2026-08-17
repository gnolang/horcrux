# Chain Node Connection Authentication

The priv validator connection between a cosigner and a chain node is always encrypted,
but by default neither end verifies who is on the other: the cosigner accepts any node
answering on the configured address, and the node accepts any signer that connects.

Each direction can be enabled independently and both are off by default.

| Cosigner has `connKeyFile` | Node has `connPubKey` | Result                                 |
| -------------------------- | --------------------- | -------------------------------------- |
| no                         | no                    | Neither end is authenticated (default) |
| yes                        | no                    | The node can authenticate the cosigner |
| no                         | yes                   | The cosigner authenticates the node    |
| yes                        | yes                   | Both ends are authenticated            |

Enabling either direction changes nothing about signing itself, and neither affects the
gRPC signing interface (`grpcAddr`) or cosigner-to-cosigner communication.

## Authenticating a cosigner to the chain nodes

Without a persistent key, a cosigner generates a new connection identity every time it
starts, so a chain node has nothing stable to authorize. Give each cosigner a persistent
identity instead:

1. On each cosigner, create the key and note the public key it prints:

    ```bash
    horcrux create-conn-key
    ```

2. Point the cosigner's `config.yaml` at it:

    ```yaml
    connKeyFile: conn_key.json
    ```

    A relative path resolves against `keyDir` when set, otherwise the home directory.
    An absolute path is used as given. If `connKeyFile` is set but the file is missing or
    unreadable, `horcrux start` fails rather than falling back to an unauthenticated
    identity.

3. Authorize every cosigner's public key on each chain node. On gno.land this is
   `allowed_kms_pubkeys` under `[consensus.priv_validator.tmkms_listener]`, which takes
   the same hex encoding `create-conn-key` prints.

The connection key is a per-cosigner identity, not shared cluster material: run
`create-conn-key` on each cosigner separately and authorize all of their public keys on
every chain node. Do not copy one key across cosigners — that gives up the ability to
tell them apart or to revoke one of them.

## Authenticating a chain node to the cosigners

Pin the node's connection public key on its `chainNodes` entry:

```yaml
chainNodes:
    - privValAddr: tcp://10.168.0.1:1234
      connPubKey: 51d0d69416ec05aa583b407898fb67b5a77149119638be95fcd0f9541ec3ffa8
    - privValAddr: tcp://10.168.0.2:1234 # unpinned, accepts any node
```

Each node has its own identity, so each entry is pinned separately, and any entry may be
left unpinned. When a node presents a different public key, the cosigner refuses the
connection, logs the expected and presented keys, and keeps retrying that node. Its
connections to the other chain nodes are unaffected, so one misconfigured or impersonated
node cannot stop the cluster from signing.

A malformed `connPubKey` behaves differently: it is rejected at startup and `horcrux start`
fails, because a pin nobody can parse is a configuration error rather than a node that
might recover. Note the case in between — a well formed pin holding the _wrong_ key is
indistinguishable from an impersonated node, so that node is never served while the rest of
the cluster keeps signing. Horcrux logs each node it is authenticating at startup; if a node
you pinned is missing from those lines, its `connPubKey` never reached the config.

### The node needs a persistent identity

Pinning only works against a chain node whose priv validator listener has a stable
identity. **Vanilla CometBFT does not**: through v0.38 it generates a fresh key for that
listener on every start (`privval/utils.go`, whose source carries the comment
`TODO: persist this key so external signer can actually authenticate us`), so its
connection public key changes at every restart and cannot usefully be pinned.

gno.land does: the node presents the key from `secrets/node_key.json`, the same identity
it uses for p2p. Read its public key as hex with:

```bash
jq -r .priv_key <node-home>/secrets/node_key.json | base64 -d | tail -c 32 | xxd -p -c 32
```

That command is for a gno.land node key, which stores the private key as a bare base64
string. It does not apply to the `conn_key.json` written by `create-conn-key`, which uses
the CometBFT encoding (`{"priv_key":{"type":…,"value":…}}`) and whose public key
`create-conn-key` already prints.

`gnoland secrets get node_id` reports the same key, but bech32 encoded (`gpub1…`), which
has to be converted to hex before it can be used as `connPubKey`.

## Cosigner-to-cosigner mutual TLS

The two directions above secure the cosigner ↔ chain-node connection. The
cosigner ↔ cosigner cluster transport (raft consensus + the Cosigner signing RPC,
served on the p2p port) is unauthenticated and unencrypted by default. Mutual TLS
closes that: it authenticates every peer by a pinned ed25519 public key and
encrypts the traffic. It is opt-in and off by default.

Nonce shares are already individually encrypted and signed, so mTLS does not
prevent key extraction (that is handled at the application layer); it protects
confidentiality of cluster traffic and blocks unauthenticated access and MITM.

### Enabling it

Each cosigner gets its own ed25519 cluster identity, and every cosigner's public
key is listed on the matching `cosigners` entry across the cluster (the allowlist).

1. On each cosigner, create its cluster key and note the printed public key:

    ```bash
    horcrux create-cluster-key
    ```

2. In each cosigner's `config.yaml`, set `clusterKeyFile` under `thresholdMode`
   and add every cosigner's `tlsPubKey` (including its own) to the `cosigners`
   entries:

    ```yaml
    thresholdMode:
        threshold: 2
        clusterKeyFile: cluster_key.json
        cosigners:
            - shardID: 1
              p2pAddr: tcp://horcrux-1:2222
              tlsPubKey: 51d0d694... # cosigner 1's cluster public key
            - shardID: 2
              p2pAddr: tcp://horcrux-2:2222
              tlsPubKey: a1b2c3d4... # cosigner 2's cluster public key
            - shardID: 3
              p2pAddr: tcp://horcrux-3:2222
              tlsPubKey: 9e8f7a6b... # cosigner 3's cluster public key
    ```

    `clusterKeyFile` resolves like other key files (relative to `keyDir`, else the
    home directory). When it is set, every `cosigners` entry must carry a valid
    `tlsPubKey`, or the process refuses to start — a partial allowlist would leave
    a peer unauthenticated.

3. Roll it out with a coordinated restart. mTLS is a hard switch: a cosigner with
   it enabled cannot talk to one without it, so provision the keys and config on
   all cosigners first, then restart them together (a brief maintenance-window
   downtime, like any upgrade). There is no mixed-mode transition.

Authentication uses self-signed certificates pinned by public key — there is no
certificate authority to run, mirroring the allowlist model already used for
cosigner-to-cosigner nonce encryption.

## Leader-only chain node connections

By default every cosigner opens its own persistent priv-validator connection to
each configured chain node. Whether that is correct depends on your topology:

- **Sharded sentries** (each cosigner dials its _own_ sentries — `sentriesPerSigner`
  with distinct nodes per cosigner): keep the default. Every sentry expects a
  connection from its assigned cosigner, and there is no single-slot contention.
- **Shared node** (multiple cosigners point at the _same_ node's priv-validator
  port — a single sentry, or a gno.land / tm2 validator): the node's listener holds
  exactly one signer connection, so the cosigners fight over that one slot. On
  CometBFT this "works" but wastes connections and lands sign requests on followers
  that must proxy to the leader; on tm2/gno.land the connection churns ~1×/second
  and the validator signs **nothing**.

For the shared-node case, set:

```yaml
thresholdMode:
    leaderOnlyChainNodeConnections: true
```

Only the current raft leader then holds the connection: followers park without
dialing, and a leader that loses leadership releases its connection so the new
leader can take the slot. The chain node always sees exactly one stable signer
connection — the model tmkms uses and the one tm2/gno.land requires. On a
leadership change there is a brief handoff (old leader drops, new leader dials and
the node re-accepts) — a block or two at worst, versus permanent churn.

Leave it off (the default) for sharded sentries: leader-only dialing would leave
follower sentries with no signer connection, which CometBFT nodes do not survive
at startup. Double-sign protection is unaffected either way — it lives at the
threshold validator's HRS high-watermark, independent of which cosigner holds the
wire.

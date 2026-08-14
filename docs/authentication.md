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

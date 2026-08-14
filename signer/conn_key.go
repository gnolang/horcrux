package signer

import (
	"encoding/hex"
	"errors"
	"fmt"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometp2p "github.com/cometbft/cometbft/p2p"
)

// ErrConnPubKeyMismatch is returned when a chain node presents a connection
// public key other than the one it is required to present.
var ErrConnPubKeyMismatch = errors.New("connection public key mismatch")

// ConnAuth is the optional authentication material for the privval connection to
// a single chain node. Each direction is independent, and the zero value
// authenticates neither.
type ConnAuth struct {
	// PrivKey is the signer's persistent connection identity, shared across every
	// chain node it connects to. When nil, the signer presents a fresh identity
	// that no chain node can pre-authorize.
	PrivKey cometcryptoed25519.PrivKey

	// NodePubKey is the connection public key the chain node is required to
	// present. When nil, any node public key is accepted.
	NodePubKey cometcryptoed25519.PubKey
}

// verifyNodePubKey checks the connection public key a chain node presented during
// the privval handshake against the key it is required to present. A nil expected
// key accepts any node.
func verifyNodePubKey(expected cometcryptoed25519.PubKey, presented cometcrypto.PubKey) error {
	if expected == nil {
		return nil
	}

	if !expected.Equals(presented) {
		return fmt.Errorf(
			"%w: expected %s, got %s",
			ErrConnPubKeyMismatch,
			hex.EncodeToString(expected.Bytes()), hex.EncodeToString(presented.Bytes()),
		)
	}

	return nil
}

// LoadConnKey reads the signer's persistent privval connection identity from a
// CometBFT node key file. Presenting a stable public key lets a chain node
// pre-authorize this signer, which a signer generating a fresh identity on every
// process start cannot satisfy.
func LoadConnKey(path string) (cometcryptoed25519.PrivKey, error) {
	nodeKey, err := cometp2p.LoadNodeKey(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load connection key %s: %w", path, err)
	}

	privKey, ok := nodeKey.PrivKey.(cometcryptoed25519.PrivKey)
	if !ok {
		return nil, fmt.Errorf("connection key %s must be ed25519, got %T", path, nodeKey.PrivKey)
	}

	// The key file is only type checked when decoded, so a truncated key reaches
	// here intact. Reject it rather than present a malformed identity.
	if len(privKey) != cometcryptoed25519.PrivateKeySize {
		return nil, fmt.Errorf(
			"connection key %s must be %d bytes, got %d",
			path, cometcryptoed25519.PrivateKeySize, len(privKey),
		)
	}

	return privKey, nil
}

// CreateConnKey generates a persistent privval connection identity and writes it
// to path as a CometBFT node key file, readable only by its owner.
func CreateConnKey(path string) (cometcryptoed25519.PrivKey, error) {
	privKey := cometcryptoed25519.GenPrivKey()

	if err := (&cometp2p.NodeKey{PrivKey: privKey}).SaveAs(path); err != nil {
		return nil, fmt.Errorf("failed to write connection key %s: %w", path, err)
	}

	return privKey, nil
}

// ConnPubKeyHex returns the hex encoded public key of a connection key, the
// encoding a chain node's list of authorized signer public keys expects.
func ConnPubKeyHex(privKey cometcryptoed25519.PrivKey) string {
	return hex.EncodeToString(privKey.PubKey().Bytes())
}

// connPubKeyFromHex decodes the hex encoded ed25519 public key that a chain node
// is required to present during the privval handshake.
func connPubKeyFromHex(pubKey string) (cometcryptoed25519.PubKey, error) {
	bz, err := hex.DecodeString(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex connection public key: %w", err)
	}

	if len(bz) != cometcryptoed25519.PubKeySize {
		return nil, fmt.Errorf(
			"connection public key must be %d bytes, got %d",
			cometcryptoed25519.PubKeySize, len(bz),
		)
	}

	return cometcryptoed25519.PubKey(bz), nil
}

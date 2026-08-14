package signer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
	"time"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/log"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	comet "github.com/cometbft/cometbft/types"
	"github.com/google/uuid"
	tsed25519 "github.com/strangelove-ventures/horcrux/v3/signer/tsed25519"
	"github.com/stretchr/testify/require"
)

// newTestCosignerForNonceSecurity builds a single 2-of-3 LocalCosigner (ID 1)
// holding a real key shard, for exercising the nonce-handling attack surface
// directly against the real sign path.
func newTestCosignerForNonceSecurity(t *testing.T) *LocalCosigner {
	t.Helper()

	const threshold, total = uint8(2), uint8(3)

	privateKey := cometcryptoed25519.GenPrivKey()
	privKeyBytes := [64]byte{}
	copy(privKeyBytes[:], privateKey[:])
	privShards := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

	rsaKeys := make([]*rsa.PrivateKey, total)
	rsaPubs := make([]*rsa.PublicKey, total)
	for i := range rsaKeys {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		rsaKeys[i] = k
		rsaPubs[i] = &k.PublicKey
	}

	cfg := Config{ThresholdModeConfig: &ThresholdModeConfig{
		Threshold: int(threshold),
		Cosigners: make(CosignersConfig, total),
	}}
	for i := range cfg.ThresholdModeConfig.Cosigners {
		cfg.ThresholdModeConfig.Cosigners[i] = CosignerConfig{ShardID: i + 1}
	}

	dir := filepath.Join(t.TempDir(), "cosigner1")
	require.NoError(t, os.Mkdir(dir, 0700))

	cosigner := NewLocalCosigner(
		log.NewNopLogger(),
		&RuntimeConfig{HomeDir: dir, StateDir: dir, Config: cfg},
		NewCosignerSecurityRSA(CosignerRSAKey{ID: 1, RSAKey: *rsaKeys[0], RSAPubs: rsaPubs}),
		"",
	)

	shardKey := CosignerEd25519Key{PubKey: privateKey.PubKey(), PrivateShard: privShards[0], ID: 1}
	keyBz, err := shardKey.MarshalJSON()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cosigner.config.KeyFilePathCosigner(testChainID), keyBz, 0600))
	require.NoError(t, cosigner.LoadSignStateIfNecessary(testChainID))
	t.Cleanup(cosigner.waitForSignStatesToFlushToDisk)

	return cosigner
}

func craftedPrecommitWithExtension(t *testing.T) (signBytes, voteExtBytes []byte) {
	t.Helper()
	vote := cometproto.Vote{
		Height:    1,
		Round:     0,
		Type:      cometproto.PrecommitType,
		Timestamp: time.Now(),
		BlockID:   cometproto.BlockID{Hash: make([]byte, 32)},
		Extension: []byte("ext"),
	}
	return comet.VoteSignBytes(testChainID, &vote), comet.VoteExtensionSignBytes(testChainID, &vote)
}

// A single SetNoncesAndSign whose vote and vote-extension UUIDs are equal must be
// rejected: signing two different messages under one nonce leaks the key shard.
func TestSetNoncesAndSignRejectsEqualUUIDs(t *testing.T) {
	cosigner := newTestCosignerForNonceSecurity(t)
	ctx := context.Background()

	u := uuid.New()
	_, err := cosigner.GetNonces(ctx, []uuid.UUID{u})
	require.NoError(t, err)

	signBytes, voteExtBytes := craftedPrecommitWithExtension(t)

	_, err = cosigner.SetNoncesAndSign(ctx, CosignerSetNoncesAndSignRequest{
		ChainID:                testChainID,
		Nonces:                 &CosignerUUIDNonces{UUID: u},
		VoteExtensionNonces:    &CosignerUUIDNonces{UUID: u},
		SignBytes:              signBytes,
		VoteExtensionSignBytes: voteExtBytes,
	})
	require.Error(t, err, "equal vote and vote-extension nonce UUIDs must be rejected")
}

// SetNoncesAndSign must reject a nil Nonces field rather than nil-deref panic.
func TestSetNoncesAndSignRejectsNilNonces(t *testing.T) {
	cosigner := newTestCosignerForNonceSecurity(t)
	signBytes, _ := craftedPrecommitWithExtension(t)

	_, err := cosigner.SetNoncesAndSign(context.Background(), CosignerSetNoncesAndSignRequest{
		ChainID:   testChainID,
		Nonces:    nil,
		SignBytes: signBytes,
	})
	require.Error(t, err)
}

// combinedNonces must not sign with fewer than threshold nonce contributions;
// otherwise a single self-only nonce is enough to produce a partial signature.
func TestSignRejectsBelowThresholdNonces(t *testing.T) {
	cosigner := newTestCosignerForNonceSecurity(t)
	ctx := context.Background()

	u := uuid.New()
	_, err := cosigner.GetNonces(ctx, []uuid.UUID{u})
	require.NoError(t, err)

	signBytes, _ := craftedPrecommitWithExtension(t)

	// Only the cosigner's own nonce is present (no peer contributions), which is
	// below the threshold of 2.
	_, err = cosigner.SetNoncesAndSign(ctx, CosignerSetNoncesAndSignRequest{
		ChainID:   testChainID,
		Nonces:    &CosignerUUIDNonces{UUID: u},
		SignBytes: signBytes,
	})
	require.Error(t, err, "signing with fewer than threshold nonces must be rejected")
}

package signer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/log"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	comet "github.com/cometbft/cometbft/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	tsed25519 "github.com/strangelove-ventures/horcrux/v3/signer/tsed25519"
)

// twoOfTwoCosigners builds a 2-of-2 cluster sharing one validator key and returns
// both local cosigners. Cosigner 1 is the one under test; cosigner 2 supplies the
// peer nonce contribution.
func twoOfTwoCosigners(t *testing.T) (c1, c2 *LocalCosigner) {
	t.Helper()
	const threshold, total = uint8(2), uint8(2)

	privateKey := cometcryptoed25519.GenPrivKey()
	privKeyBytes := [64]byte{}
	copy(privKeyBytes[:], privateKey[:])
	shards := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

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

	mk := func(id int) *LocalCosigner {
		dir := filepath.Join(t.TempDir(), fmt.Sprintf("cosigner%d", id))
		require.NoError(t, os.Mkdir(dir, 0700))
		lc := NewLocalCosigner(
			log.NewNopLogger(),
			&RuntimeConfig{HomeDir: dir, StateDir: dir, Config: cfg},
			NewCosignerSecurityRSA(CosignerRSAKey{ID: id, RSAKey: *rsaKeys[id-1], RSAPubs: rsaPubs}),
			"",
		)
		key := CosignerEd25519Key{PubKey: privateKey.PubKey(), PrivateShard: shards[id-1], ID: id}
		keyBz, err := key.MarshalJSON()
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(lc.config.KeyFilePathCosigner(testChainID), keyBz, 0600))
		require.NoError(t, lc.LoadSignStateIfNecessary(testChainID))
		t.Cleanup(lc.waitForSignStatesToFlushToDisk)
		return lc
	}

	return mk(1), mk(2)
}

// precommitBytes builds sign bytes for a precommit at the given height with a
// BlockID derived from tag, so two tags produce two materially different blocks.
func precommitBytes(height int64, tag string) []byte {
	h := sha256.Sum256([]byte(tag))
	vote := cometproto.Vote{
		Height:  height,
		Round:   0,
		Type:    cometproto.PrecommitType,
		BlockID: cometproto.BlockID{Hash: h[:]},
	}
	return comet.VoteSignBytes(testChainID, &vote)
}

// buildSignReq prepares nonces for one block at one HRS and returns a ready
// SetNoncesAndSign request for cosigner 1, with cosigner 2's contribution.
func buildSignReq(t *testing.T, ctx context.Context, c1, c2 *LocalCosigner, height int64, tag string) CosignerSetNoncesAndSignRequest {
	t.Helper()
	u := uuid.New()

	_, err := c1.GetNonces(ctx, []uuid.UUID{u})
	require.NoError(t, err)
	peer, err := c2.GetNonces(ctx, []uuid.UUID{u})
	require.NoError(t, err)

	// cosigner 2's nonce contribution destined for cosigner 1.
	var forC1 []CosignerNonce
	for _, n := range peer[0].Nonces {
		if n.DestinationID == 1 {
			forC1 = append(forC1, n)
		}
	}

	return CosignerSetNoncesAndSignRequest{
		ChainID:   testChainID,
		Nonces:    &CosignerUUIDNonces{UUID: u, Nonces: forC1},
		HRST:      HRSTKey{Height: height, Round: 0, Step: 2},
		SignBytes: precommitBytes(height, tag),
	}
}

// TestCosignerConcurrentDifferentBlocksSameHRS asserts that a single cosigner
// never returns valid signatures over two different blocks at the same HRS, even
// when two such requests are issued concurrently.
func TestCosignerConcurrentDifferentBlocksSameHRS(t *testing.T) {
	ctx := context.Background()
	c1, c2 := twoOfTwoCosigners(t)

	const rounds = 40
	for i := 0; i < rounds; i++ {
		height := int64(i + 1)

		reqA := buildSignReq(t, ctx, c1, c2, height, "blockA")
		reqB := buildSignReq(t, ctx, c1, c2, height, "blockB")

		var wg sync.WaitGroup
		wg.Add(2)
		var okA, okB bool
		go func() { defer wg.Done(); _, err := c1.SetNoncesAndSign(ctx, reqA); okA = err == nil }()
		go func() { defer wg.Done(); _, err := c1.SetNoncesAndSign(ctx, reqB); okB = err == nil }()
		wg.Wait()

		require.Falsef(t, okA && okB,
			"cosigner signed two different blocks at height %d (double sign)", height)
		_ = time.Now
	}
}

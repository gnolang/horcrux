package signer

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/tmhash"
	cometlog "github.com/cometbft/cometbft/libs/log"
	cometrand "github.com/cometbft/cometbft/libs/rand"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/require"
)

// failOnceCosigner fails the first SetNoncesAndSign and serves every later
// call, modeling a cosigner that hiccups during one attempt and is healthy for
// the retry.
type failOnceCosigner struct {
	Cosigner
	failed atomic.Bool
}

func (c *failOnceCosigner) SetNoncesAndSign(
	ctx context.Context,
	req CosignerSetNoncesAndSignRequest,
) (*CosignerSignResponse, error) {
	if c.failed.CompareAndSwap(false, true) {
		return nil, errors.New("injected transient cosigner failure")
	}
	return c.Cosigner.SetNoncesAndSign(ctx, req)
}

// A retry of a failed attempt must produce a valid signature. The first
// attempt fails after some cosigners already produced and saved their shares
// under that attempt's nonce round; the retry runs under a fresh round, and a
// cosigner that re-serves its saved share hands the leader a share that cannot
// combine with the fresh ones — the combine fails verification and the retry
// is lost. Every share in a combine must come from the round the leader
// distributed for it.
func TestThresholdValidatorRetryAfterFailedAttempt(t *testing.T) {
	cosigners, pubKey := getTestLocalCosigners(t, 2, 2)
	peer := &failOnceCosigner{Cosigner: cosigners[1]}
	leader := &MockLeader{id: 1}
	validator := NewThresholdValidator(
		cometlog.NewNopLogger(), cosigners[0].config, 2, time.Second, 1,
		cosigners[0], []Cosigner{peer}, leader,
	)
	leader.leader = validator
	t.Cleanup(validator.Stop)
	require.NoError(t, validator.LoadSignStateIfNecessary(testChainID))
	ctx := context.Background()

	hash := cometrand.Bytes(tmhash.Size)
	vote := cometproto.Vote{
		Height: 1,
		Round:  1,
		Type:   cometproto.PrevoteType,
		BlockID: cometproto.BlockID{
			Hash:          hash,
			PartSetHeader: cometproto.PartSetHeader{Total: 1, Hash: hash},
		},
		Timestamp: time.Now(),
	}

	// Two attempts, one nonce round each, plus slack.
	validator.nonceCache.LoadN(ctx, 4)

	_, _, _, err := validator.Sign(ctx, testChainID, VoteToBlock(testChainID, &vote))
	require.Error(t, err, "the first attempt must fail")
	require.True(t, peer.failed.Load(),
		"the injected failure must be what failed the first attempt")

	// The leader's own cosigner produced and saved its share during the failed
	// attempt — the precondition that makes the retry hit the byte-identical
	// gate with a share from the earlier nonce round.
	leaderState, err := cosigners[0].getChainState(testChainID)
	require.NoError(t, err)
	require.Equal(t, vote.Height, leaderState.lastSignState.LatestHRS().Height,
		"the leader's cosigner must have saved its share during the failed attempt")

	// The same node retries the identical vote; the cluster draws a fresh nonce
	// round for it.
	sig, _, stamp, err := validator.Sign(ctx, testChainID, VoteToBlock(testChainID, &vote))
	require.NoError(t, err, "the retry must succeed once every cosigner is healthy")

	signed := vote
	signed.Timestamp = stamp
	require.True(t, pubKey.VerifySignature(VoteToBlock(testChainID, &signed).SignBytes, sig),
		"the retry's combined signature must verify")

	// A later identical request is served from the completed signature.
	resig, _, restamp, err := validator.Sign(ctx, testChainID, VoteToBlock(testChainID, &vote))
	require.NoError(t, err)
	require.True(t, bytes.Equal(sig, resig))
	require.True(t, stamp.Equal(restamp))
}

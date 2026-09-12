package signer

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/tmhash"
	cometlog "github.com/cometbft/cometbft/libs/log"
	cometrand "github.com/cometbft/cometbft/libs/rand"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// TestThresholdValidatorMultipleSentriesSameHRS asserts that two chain nodes
// sharing one validator identity end up broadcasting the same vote.
//
// Each node stamps its own vote before asking for a signature, so two nodes voting
// on the same block send sign requests whose payloads differ only by timestamp.
// Signing each of them yields two different, equally valid signatures over the same
// height/round/step, and a peer holding one of them rejects the other with
// ErrVoteNonDeterministicSignature. The second request must instead be answered
// with the first signature and the timestamp it was made over.
func TestThresholdValidatorMultipleSentriesSameHRS(t *testing.T) {
	t.Parallel()

	const threshold, total = uint8(2), uint8(3)

	for _, tc := range []struct {
		name       string
		concurrent bool
		height     int64
	}{
		// Both sentries request a signature before either request completes.
		{name: "concurrent", concurrent: true, height: 1},
		// The second sentry requests a signature once the first one is signed.
		{name: "sequential", concurrent: false, height: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cosigners, pubKey := getTestLocalCosigners(t, threshold, total)

			thresholdCosigners := make([]Cosigner, 0, threshold-1)
			for i, cosigner := range cosigners {
				if i != 0 && len(thresholdCosigners) != int(threshold)-1 {
					thresholdCosigners = append(thresholdCosigners, cosigner)
				}
			}

			leader := &MockLeader{id: 1}
			validator := NewThresholdValidator(
				cometlog.NewNopLogger(),
				cosigners[0].config,
				int(threshold),
				time.Second,
				1,
				cosigners[0],
				thresholdCosigners,
				leader,
			)
			defer validator.Stop()
			leader.leader = validator

			ctx := context.Background()
			require.NoError(t, validator.LoadSignStateIfNecessary(testChainID))

			hash := cometrand.Bytes(tmhash.Size)
			blockID := cometproto.BlockID{
				Hash:          hash,
				PartSetHeader: cometproto.PartSetHeader{Total: 1, Hash: hash},
			}

			// The same prevote, as stamped by two sentries a couple of milliseconds apart.
			sentry1 := cometproto.Vote{
				Height:    tc.height,
				Round:     1,
				Type:      cometproto.PrevoteType,
				BlockID:   blockID,
				Timestamp: time.Now(),
			}
			sentry2 := sentry1
			sentry2.Timestamp = sentry1.Timestamp.Add(2 * time.Millisecond)

			validator.nonceCache.LoadN(ctx, 4)

			var sig1, sig2 []byte
			var stamp1, stamp2 time.Time

			sign := func(vote *cometproto.Vote, sig *[]byte, stamp *time.Time) func() error {
				return func() error {
					s, _, ts, err := validator.Sign(ctx, testChainID, VoteToBlock(testChainID, vote))
					*sig, *stamp = s, ts

					return err
				}
			}

			if tc.concurrent {
				var eg errgroup.Group
				eg.Go(sign(&sentry1, &sig1, &stamp1))
				eg.Go(sign(&sentry2, &sig2, &stamp2))
				require.NoError(t, eg.Wait())
			} else {
				require.NoError(t, sign(&sentry1, &sig1, &stamp1)())
				require.NoError(t, sign(&sentry2, &sig2, &stamp2)())
			}

			// Both sentries must end up with the same signature over the same timestamp,
			// otherwise each broadcasts a vote the other's peers reject.
			require.True(t, bytes.Equal(sig1, sig2), "same HRS signed twice with different signatures")
			require.True(t, stamp1.Equal(stamp2), "same HRS signed over two different timestamps")

			// Each node stamps its vote with the timestamp the signer returned, so both
			// votes must verify.
			sentry1.Timestamp, sentry2.Timestamp = stamp1, stamp2
			require.True(t, pubKey.VerifySignature(VoteToBlock(testChainID, &sentry1).SignBytes, sig1))
			require.True(t, pubKey.VerifySignature(VoteToBlock(testChainID, &sentry2).SignBytes, sig2))
		})
	}
}

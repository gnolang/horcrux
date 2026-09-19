package signer

import (
	"bytes"
	"context"
	"testing"
	"time"

	cometcrypto "github.com/cometbft/cometbft/crypto"
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
			validator, pubKey := newMultiSentryTestValidator(t, threshold, total)
			defer validator.Stop()

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

// TestThresholdValidatorMultipleSentriesSameProposal asserts the same for proposals.
//
// Two chain nodes sharing one validator identity are both the proposer at the same
// height and round, and each stamps its own proposal before asking for a signature.
// The second request is answered with the first signature, so it must also be
// answered with the timestamp that signature was made over: a proposal stamped with
// anything else carries a signature that does not cover it, and peers reject it.
func TestThresholdValidatorMultipleSentriesSameProposal(t *testing.T) {
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
			validator, pubKey := newMultiSentryTestValidator(t, threshold, total)
			defer validator.Stop()

			ctx := context.Background()
			require.NoError(t, validator.LoadSignStateIfNecessary(testChainID))

			hash := cometrand.Bytes(tmhash.Size)
			blockID := cometproto.BlockID{
				Hash:          hash,
				PartSetHeader: cometproto.PartSetHeader{Total: 1, Hash: hash},
			}

			// The same proposal, as stamped by two sentries a couple of milliseconds apart.
			sentry1 := cometproto.Proposal{
				Height:    tc.height,
				Round:     1,
				Type:      cometproto.ProposalType,
				BlockID:   blockID,
				Timestamp: time.Now(),
			}
			sentry2 := sentry1
			sentry2.Timestamp = sentry1.Timestamp.Add(2 * time.Millisecond)

			validator.nonceCache.LoadN(ctx, 4)

			var sig1, sig2 []byte
			var stamp1, stamp2 time.Time

			sign := func(proposal *cometproto.Proposal, sig *[]byte, stamp *time.Time) func() error {
				return func() error {
					s, _, ts, err := validator.Sign(ctx, testChainID, ProposalToBlock(testChainID, proposal))
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

			require.True(t, bytes.Equal(sig1, sig2), "same HRS signed twice with different signatures")
			require.True(t, stamp1.Equal(stamp2), "same HRS signed over two different timestamps")

			// Each node stamps its proposal with the timestamp the signer returned, so
			// both proposals must verify.
			sentry1.Timestamp, sentry2.Timestamp = stamp1, stamp2
			require.True(t, pubKey.VerifySignature(ProposalToBlock(testChainID, &sentry1).SignBytes, sig1))
			require.True(t, pubKey.VerifySignature(ProposalToBlock(testChainID, &sentry2).SignBytes, sig2))
		})
	}
}

// A proposal for an already signed HRS with a DIFFERENT block must never mint a
// new signature: the existing signature is returned with the timestamp it was
// made over. That signature does not verify over the conflicting proposal — the
// node broadcasts it and peers reject it — which is the safe outcome: the
// signer holds one signature per proposal HRS, and a conflicting payload can
// never obtain a second one.
func TestThresholdValidatorConflictingProposalGetsExistingSignature(t *testing.T) {
	t.Parallel()

	validator, pubKey := newMultiSentryTestValidator(t, 2, 3)
	defer validator.Stop()

	ctx := context.Background()
	require.NoError(t, validator.LoadSignStateIfNecessary(testChainID))

	hash := cometrand.Bytes(tmhash.Size)
	first := cometproto.Proposal{
		Height: 1,
		Round:  1,
		Type:   cometproto.ProposalType,
		BlockID: cometproto.BlockID{
			Hash:          hash,
			PartSetHeader: cometproto.PartSetHeader{Total: 1, Hash: hash},
		},
		Timestamp: time.Now(),
	}

	validator.nonceCache.LoadN(ctx, 2)

	sig, _, stamp, err := validator.Sign(ctx, testChainID, ProposalToBlock(testChainID, &first))
	require.NoError(t, err)

	conflictingHash := cometrand.Bytes(tmhash.Size)
	conflicting := first
	conflicting.BlockID = cometproto.BlockID{
		Hash:          conflictingHash,
		PartSetHeader: cometproto.PartSetHeader{Total: 1, Hash: conflictingHash},
	}
	conflicting.Timestamp = first.Timestamp.Add(2 * time.Millisecond)

	conflictingSig, _, conflictingStamp, err := validator.Sign(
		ctx, testChainID, ProposalToBlock(testChainID, &conflicting))
	require.NoError(t, err)

	require.True(t, bytes.Equal(sig, conflictingSig),
		"a conflicting proposal must receive the existing signature, never a new one")
	require.True(t, stamp.Equal(conflictingStamp),
		"the existing signature must come with the timestamp it was made over")

	// The returned signature covers the first proposal, not the conflicting one.
	first.Timestamp = stamp
	require.True(t, pubKey.VerifySignature(ProposalToBlock(testChainID, &first).SignBytes, sig))
	conflicting.Timestamp = conflictingStamp
	require.False(t, pubKey.VerifySignature(ProposalToBlock(testChainID, &conflicting).SignBytes, conflictingSig))
}

// newMultiSentryTestValidator builds a threshold validator backed by local cosigners,
// with itself as the raft leader so Sign runs the signing process rather than proxying.
func newMultiSentryTestValidator(
	t *testing.T,
	threshold, total uint8,
) (*ThresholdValidator, cometcrypto.PubKey) {
	t.Helper()

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
	leader.leader = validator

	return validator, pubKey
}

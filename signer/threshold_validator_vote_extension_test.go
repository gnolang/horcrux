package signer

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	cometlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/libs/protoio"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/google/uuid"
	"github.com/strangelove-ventures/horcrux/v3/signer/proto"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func newVoteExtensionTestValidator(t *testing.T) (*ThresholdValidator, []*LocalCosigner, cometcrypto.PubKey) {
	t.Helper()
	cosigners, pubKey := getTestLocalCosigners(t, 2, 2)
	leader := &MockLeader{id: 1}
	validator := NewThresholdValidator(
		cometlog.NewNopLogger(), cosigners[0].config, 2, time.Second, 1,
		cosigners[0], []Cosigner{cosigners[1]}, leader,
	)
	leader.leader = validator
	t.Cleanup(validator.Stop)
	require.NoError(t, validator.LoadSignStateIfNecessary(testChainID))
	return validator, cosigners, pubKey
}

func voteWithExtension(extension string) cometproto.Vote {
	return cometproto.Vote{
		Height: 1, Round: 1, Type: cometproto.PrecommitType,
		Timestamp: time.Date(2026, time.September, 14, 12, 0, 0, 123456789, time.UTC),
		BlockID: cometproto.BlockID{
			Hash:          bytes.Repeat([]byte{1}, 32),
			PartSetHeader: cometproto.PartSetHeader{Total: 1, Hash: bytes.Repeat([]byte{2}, 32)},
		},
		Extension: []byte(extension),
	}
}

func TestThresholdValidatorChangedVoteExtension(t *testing.T) {
	for _, tc := range []struct {
		name       string
		delay      time.Duration
		concurrent bool
		extension  string
	}{
		{name: "same timestamp", extension: "second"},
		{name: "different timestamp", delay: time.Millisecond, extension: "second"},
		{name: "empty extension", delay: time.Millisecond},
		{name: "concurrent", delay: time.Millisecond, concurrent: true, extension: "second"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			validator, _, pubKey := newVoteExtensionTestValidator(t)
			votes := []cometproto.Vote{voteWithExtension("first"), voteWithExtension(tc.extension)}
			votes[1].Timestamp = votes[1].Timestamp.Add(tc.delay)
			var signatures, extensions [2][]byte
			var timestamps [2]time.Time
			sign := func(i int) error {
				var err error
				signatures[i], extensions[i], timestamps[i], err = validator.Sign(
					context.Background(), testChainID, VoteToBlock(testChainID, &votes[i]),
				)
				return err
			}
			if tc.concurrent {
				var eg errgroup.Group
				eg.Go(func() error { return sign(0) })
				eg.Go(func() error { return sign(1) })
				require.NoError(t, eg.Wait())
			} else {
				require.NoError(t, sign(0))
				require.NoError(t, sign(1))
			}
			require.Equal(t, signatures[0], signatures[1])
			require.True(t, timestamps[0].Equal(timestamps[1]))
			for i := range votes {
				votes[i].Timestamp = timestamps[i]
				block := VoteToBlock(testChainID, &votes[i])
				require.True(t, pubKey.VerifySignature(block.SignBytes, signatures[i]))
				require.True(t, pubKey.VerifySignature(block.VoteExtensionSignBytes, extensions[i]),
					"extension signature must cover the extension requested by sentry %d", i)
			}
		})
	}
}

// Observe actual signing operations, including the public nonce contributions,
// so retries cannot accidentally re-sign the vote or reuse extension nonces.
type recordingExtensionSigner struct {
	ThresholdSigner
	mu       sync.Mutex
	payloads [][]byte
	nonces   [][][]byte
	fail     []byte
}

func (s *recordingExtensionSigner) Sign(nonces []Nonce, payload []byte) ([]byte, error) {
	s.mu.Lock()
	s.payloads = append(s.payloads, bytes.Clone(payload))
	pubKeys := make([][]byte, len(nonces))
	for i, nonce := range nonces {
		pubKeys[i] = bytes.Clone(nonce.PubKey)
	}
	s.nonces = append(s.nonces, pubKeys)
	fail := bytes.Equal(payload, s.fail)
	s.mu.Unlock()
	if fail {
		return nil, errors.New("injected extension signing failure")
	}
	return s.ThresholdSigner.Sign(nonces, payload)
}

func TestThresholdValidatorVoteExtensionFailurePreservesVote(t *testing.T) {
	validator, cosigners, pubKey := newVoteExtensionTestValidator(t)
	state, err := cosigners[0].getChainState(testChainID)
	require.NoError(t, err)
	recorder := &recordingExtensionSigner{ThresholdSigner: state.signer}
	state.signer = recorder
	ctx := context.Background()
	vote := voteWithExtension("first")
	originalBlock := VoteToBlock(testChainID, &vote)
	sig, extSig, stamp, err := validator.Sign(ctx, testChainID, originalBlock)
	require.NoError(t, err)

	vote.Extension = []byte("second")
	vote.Timestamp = vote.Timestamp.Add(time.Millisecond)
	block := VoteToBlock(testChainID, &vote)
	recorder.fail = block.VoteExtensionSignBytes
	_, _, _, err = validator.Sign(ctx, testChainID, block)
	require.Error(t, err)

	// The original completed vote must survive the failed extension retry.
	cachedSig, cachedExtSig, cachedStamp, err := validator.Sign(ctx, testChainID, originalBlock)
	require.NoError(t, err)
	require.Equal(t, sig, cachedSig)
	require.Equal(t, extSig, cachedExtSig)
	require.True(t, stamp.Equal(cachedStamp))

	recorder.fail = nil
	retrySig, retryExtSig, retryStamp, err := validator.Sign(ctx, testChainID, block)
	require.NoError(t, err)
	require.Equal(t, sig, retrySig)
	require.True(t, stamp.Equal(retryStamp))
	require.True(t, pubKey.VerifySignature(block.VoteExtensionSignBytes, retryExtSig))

	voteSigns := 0
	seenNonces := make(map[string]bool)
	for i, payload := range recorder.payloads {
		if bytes.Equal(payload, originalBlock.SignBytes) {
			voteSigns++
		}
		for _, pubKey := range recorder.nonces[i] {
			require.False(t, seenNonces[string(pubKey)], "a public nonce was reused across signing operations")
			seenNonces[string(pubKey)] = true
		}
	}
	require.Equal(t, 1, voteSigns, "extension retries must not sign the vote again")
}

func TestThresholdValidatorVoteExtensionAfterStateChange(t *testing.T) {
	for _, restart := range []bool{false, true} {
		name := "after advancing the round"
		if restart {
			name = "after reloading persisted state"
		}
		t.Run(name, func(t *testing.T) {
			validator, cosigners, pubKey := newVoteExtensionTestValidator(t)
			ctx := context.Background()
			vote := voteWithExtension("first")
			sig, _, stamp, err := validator.Sign(ctx, testChainID, VoteToBlock(testChainID, &vote))
			require.NoError(t, err)
			if restart {
				validator.Stop()
				validator.chainState.Delete(testChainID)
				for _, cosigner := range cosigners {
					cosigner.waitForSignStatesToFlushToDisk()
					cosigner.chainState.Delete(testChainID)
				}
				require.NoError(t, validator.LoadSignStateIfNecessary(testChainID))
			} else {
				// Another sentry drives the round forward while this one retries.
				// The watermark moves past the vote, but stays within its height.
				next := vote
				next.Round++
				_, _, _, err := validator.Sign(ctx, testChainID, VoteToBlock(testChainID, &next))
				require.NoError(t, err)
			}
			css := validator.mustLoadChainState(testChainID)
			latest, _ := css.lastSignState.GetFromCache(HRSKey{})
			vote.Extension = []byte("second")
			vote.Timestamp = vote.Timestamp.Add(time.Millisecond)
			block := VoteToBlock(testChainID, &vote)
			retrySig, extSig, retryStamp, err := validator.Sign(ctx, testChainID, block)
			require.NoError(t, err)
			require.Equal(t, sig, retrySig)
			require.True(t, stamp.Equal(retryStamp))
			require.True(t, pubKey.VerifySignature(block.VoteExtensionSignBytes, extSig))
			after, _ := css.lastSignState.GetFromCache(HRSKey{})
			require.Equal(t, latest, after, "extension signing must not move the vote watermark")
			for _, cosigner := range cosigners {
				state, err := cosigner.getChainState(testChainID)
				require.NoError(t, err)
				after, _ := state.lastSignState.GetFromCache(HRSKey{})
				require.Equal(t, latest, after)
			}
		})
	}
}

func TestThresholdValidatorVoteExtensionRejectsConflicts(t *testing.T) {
	validator, _, _ := newVoteExtensionTestValidator(t)
	ctx := context.Background()
	vote := voteWithExtension("first")
	_, _, _, err := validator.Sign(ctx, testChainID, VoteToBlock(testChainID, &vote))
	require.NoError(t, err)

	conflict := vote
	conflict.BlockID.Hash = bytes.Repeat([]byte{3}, 32)
	conflict.Extension = []byte("second")
	conflict.Timestamp = conflict.Timestamp.Add(time.Millisecond)
	_, _, _, err = validator.Sign(ctx, testChainID, VoteToBlock(testChainID, &conflict))
	var blockErr *DiffBlockIDsError
	require.ErrorAs(t, err, &blockErr)

	// An unchanged vote must not bypass validation of the extension's metadata.
	for _, extension := range []cometproto.CanonicalVoteExtension{
		{Height: vote.Height, Round: int64(vote.Round), ChainId: "another-chain"},
		{Height: vote.Height + 1, Round: int64(vote.Round), ChainId: testChainID},
		{Height: vote.Height, Round: int64(vote.Round) + 1, ChainId: testChainID},
	} {
		block := VoteToBlock(testChainID, &vote)
		block.VoteExtensionSignBytes, err = protoio.MarshalDelimited(&extension)
		require.NoError(t, err)
		_, _, _, err = validator.Sign(ctx, testChainID, block)
		require.Error(t, err)
	}
}

func TestLocalCosignerCachedVoteExtensionRejectsNonceReuse(t *testing.T) {
	validator, cosigners, _ := newVoteExtensionTestValidator(t)
	ctx := context.Background()
	vote := voteWithExtension("first")
	_, _, _, err := validator.Sign(ctx, testChainID, VoteToBlock(testChainID, &vote))
	require.NoError(t, err)
	vote.Extension = []byte("second")
	block := VoteToBlock(testChainID, &vote)
	nonces, err := validator.getNoncesFallback(ctx, 2)
	require.NoError(t, err)
	req := CosignerSetNoncesAndSignRequest{
		ChainID: testChainID, HRST: block.HRSTKey(), SignBytes: block.SignBytes,
		Nonces:                 nonces.Nonces[0].For(cosigners[0].GetID()),
		VoteExtensionNonces:    nonces.Nonces[1].For(cosigners[0].GetID()),
		VoteExtensionSignBytes: block.VoteExtensionSignBytes,
	}
	_, err = cosigners[0].SetNoncesAndSign(ctx, req)
	require.NoError(t, err)
	vote.Extension = []byte("third")
	req.VoteExtensionSignBytes = VoteToBlock(testChainID, &vote).VoteExtensionSignBytes
	_, err = cosigners[0].SetNoncesAndSign(ctx, req)
	require.Error(t, err, "a used extension nonce must not sign a second payload")

	u := uuid.New()
	_, err = cosigners[0].sign(CosignerSignRequest{
		ChainID: testChainID, SignBytes: block.SignBytes,
		UUID: u, VoteExtUUID: u, VoteExtensionSignBytes: block.VoteExtensionSignBytes,
	})
	require.ErrorContains(t, err, "nonce UUIDs must differ")
}

func voteExtensionRPCClient(t *testing.T, server *CosignerGRPCServer) proto.CosignerClient {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	rpc := grpc.NewServer()
	proto.RegisterCosignerServer(rpc, server)
	go func() { _ = rpc.Serve(listener) }()
	t.Cleanup(rpc.Stop)
	conn, err := grpc.NewClient("passthrough:///cosigner-test",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return proto.NewCosignerClient(conn)
}

func TestThresholdValidatorVoteExtensionThroughProxy(t *testing.T) {
	validator, cosigners, pubKey := newVoteExtensionTestValidator(t)
	logger := cometlog.NewNopLogger()
	// Exercise both RPC boundaries: follower -> leader and leader -> cosigner.
	validator.peerCosigners[0] = &RemoteCosigner{
		id: 2,
		client: voteExtensionRPCClient(t, NewCosignerGRPCServer(
			cosigners[1], nil, &RaftStore{logger: logger},
		)),
	}
	leaderPeer := &RemoteCosigner{
		id: 1,
		client: voteExtensionRPCClient(t, NewCosignerGRPCServer(
			cosigners[0], validator, &RaftStore{logger: logger},
		)),
	}
	follower := NewThresholdValidator(
		logger, cosigners[1].config, 2, time.Second, 1, cosigners[1], []Cosigner{leaderPeer},
		&MockLeader{id: 1, leader: &ThresholdValidator{myCosigner: cosigners[1]}},
	)
	t.Cleanup(follower.Stop)
	remoteSigner := NewReconnRemoteSigner(
		"tcp://127.0.0.1:0", logger, follower, net.Dialer{}, 1024*1024, ConnAuth{}, nil,
	)
	vote := voteWithExtension("first")
	ctx := context.Background()
	first, drop := remoteSigner.handleSignVoteRequest(ctx, testChainID, &vote)
	require.False(t, drop)
	require.Nil(t, first.GetSignedVoteResponse().Error)
	vote.Timestamp = vote.Timestamp.Add(time.Millisecond)
	vote.Extension = []byte("second")
	second, drop := remoteSigner.handleSignVoteRequest(ctx, testChainID, &vote)
	require.False(t, drop)
	response := second.GetSignedVoteResponse()
	require.Nil(t, response.Error)
	require.Equal(t, vote.Extension, response.Vote.Extension)
	require.Equal(t, first.GetSignedVoteResponse().Vote.Signature, response.Vote.Signature)
	require.True(t, first.GetSignedVoteResponse().Vote.Timestamp.Equal(response.Vote.Timestamp))
	block := VoteToBlock(testChainID, &response.Vote)
	require.True(t, pubKey.VerifySignature(block.SignBytes, response.Vote.Signature))
	require.True(t, pubKey.VerifySignature(block.VoteExtensionSignBytes, response.Vote.ExtensionSignature))
}

// voteExtensionRound assembles, for each cosigner in signers, the nonce
// contributions destined for it from the rest of the set. This mirrors what the
// leader distributes in signVoteExtension: one nonce round for the vote and a
// separate one for the extension.
func voteExtensionRound(
	ctx context.Context, t *testing.T, signers []*LocalCosigner, block Block,
) []CosignerSetNoncesAndSignRequest {
	t.Helper()
	uuids := []uuid.UUID{uuid.New(), uuid.New()}
	// contributions[target][round] holds the nonces target needs for that round.
	contributions := make([][2][]CosignerNonce, len(signers))
	for _, source := range signers {
		nonces, err := source.GetNonces(ctx, uuids)
		require.NoError(t, err)
		for round, uuidNonces := range nonces {
			require.Equal(t, uuids[round], uuidNonces.UUID)
			for _, nonce := range uuidNonces.Nonces {
				for target, cosigner := range signers {
					if nonce.DestinationID == cosigner.GetID() {
						contributions[target][round] = append(contributions[target][round], nonce)
					}
				}
			}
		}
	}
	reqs := make([]CosignerSetNoncesAndSignRequest, len(signers))
	for target := range signers {
		reqs[target] = CosignerSetNoncesAndSignRequest{
			ChainID:                testChainID,
			HRST:                   block.HRSTKey(),
			SignBytes:              block.SignBytes,
			Nonces:                 &CosignerUUIDNonces{UUID: uuids[0], Nonces: contributions[target][0]},
			VoteExtensionSignBytes: block.VoteExtensionSignBytes,
			VoteExtensionNonces:    &CosignerUUIDNonces{UUID: uuids[1], Nonces: contributions[target][1]},
		}
	}
	return reqs
}

// The extension round draws any threshold of cosigners, so it can include one
// that sat out the original vote. That cosigner has to sign the vote itself
// before it can sign the extension; only its extension share is combined.
func TestLocalCosignerVoteExtensionForUnsignedVote(t *testing.T) {
	cosigners, pubKey := getTestLocalCosigners(t, 2, 3)
	leader := &MockLeader{id: 1}
	validator := NewThresholdValidator(
		cometlog.NewNopLogger(), cosigners[0].config, 2, time.Second, 1,
		cosigners[0], []Cosigner{cosigners[1]}, leader,
	)
	leader.leader = validator
	t.Cleanup(validator.Stop)
	require.NoError(t, validator.LoadSignStateIfNecessary(testChainID))

	ctx := context.Background()
	vote := voteWithExtension("first")
	// Cosigners 1 and 2 sign the vote; cosigner 3 never sees it.
	sig, _, stamp, err := validator.Sign(ctx, testChainID, VoteToBlock(testChainID, &vote))
	require.NoError(t, err)
	vote.Timestamp = stamp

	require.NoError(t, cosigners[2].LoadSignStateIfNecessary(testChainID))
	absent, err := cosigners[2].getChainState(testChainID)
	require.NoError(t, err)
	require.Zero(t, absent.lastSignState.Height, "cosigner 3 must not have signed the vote")

	// Retry with a changed extension over the cosigners that include the absentee.
	vote.Extension = []byte("second")
	block := VoteToBlock(testChainID, &vote)
	signers := []*LocalCosigner{cosigners[0], cosigners[2]}
	shares := make([]PartialSignature, len(signers))
	for i, req := range voteExtensionRound(ctx, t, signers, block) {
		res, err := signers[i].SetNoncesAndSign(ctx, req)
		require.NoError(t, err)
		require.NotEmpty(t, res.VoteExtensionSignature)
		shares[i] = PartialSignature{ID: signers[i].GetID(), Signature: res.VoteExtensionSignature}
	}
	extSig, err := cosigners[0].CombineSignatures(testChainID, shares)
	require.NoError(t, err)
	require.True(t, pubKey.VerifySignature(block.VoteExtensionSignBytes, extSig))

	// The absentee signed the vote to reach the extension, and the vote it signed
	// is the cached one, so the full signature the sentry already holds stands.
	require.Equal(t, vote.Height, absent.lastSignState.Height)
	require.Equal(t, block.SignBytes, []byte(absent.lastSignState.SignBytes))
	require.NotEqual(t, sig, absent.lastSignState.Signature, "a share is not the full signature")
}

// A cosigner that both sat out the vote and moved past its height has nothing to
// check the extension against, so it refuses rather than sign an unseen vote.
func TestLocalCosignerVoteExtensionRefusedAfterRegression(t *testing.T) {
	cosigners, _ := getTestLocalCosigners(t, 2, 3)
	ctx := context.Background()
	vote := voteWithExtension("first")
	block := VoteToBlock(testChainID, &vote)

	later := vote
	later.Height++
	laterBlock := VoteToBlock(testChainID, &later)
	signers := []*LocalCosigner{cosigners[0], cosigners[2]}
	for i, req := range voteExtensionRound(ctx, t, signers, laterBlock) {
		_, err := signers[i].SetNoncesAndSign(ctx, req)
		require.NoError(t, err)
	}

	for i, req := range voteExtensionRound(ctx, t, signers, block) {
		_, err := signers[i].SetNoncesAndSign(ctx, req)
		require.Error(t, err, "cosigner %d must refuse an extension for a vote it never made", signers[i].GetID())
	}
}

// Signing an extension is bounded to the height the cosigner is on. The extension
// is opaque application data a cosigner cannot check, so serving one for a height
// it has already moved past would let a leader obtain a threshold signature over
// extension bytes of its choosing for a block that is already decided -- something
// a request for a fresh vote at the current height cannot reach. The vote itself is
// still cached and still refused for anything but an exact match.
func TestThresholdValidatorVoteExtensionRefusedAfterHeightAdvance(t *testing.T) {
	validator, _, _ := newVoteExtensionTestValidator(t)
	ctx := context.Background()

	vote := voteWithExtension("first")
	sig, _, stamp, err := validator.Sign(ctx, testChainID, VoteToBlock(testChainID, &vote))
	require.NoError(t, err)
	vote.Timestamp = stamp

	next := vote
	next.Height++
	_, _, _, err = validator.Sign(ctx, testChainID, VoteToBlock(testChainID, &next))
	require.NoError(t, err)

	// Same vote, changed extension, now a height behind the watermark.
	retry := vote
	retry.Extension = []byte("second")
	_, _, _, err = validator.Sign(ctx, testChainID, VoteToBlock(testChainID, &retry))
	require.Error(t, err, "an extension for a passed height must not be signed")
	// The height has passed, so no retry can ever succeed: answer the sentry with a
	// terminal refusal rather than dropping the connection for it to try again.
	require.True(t, signRefusal(err), "a passed height is a refusal, not a transient failure")
	var heightRegression *HeightRegressionError
	require.ErrorAs(t, err, &heightRegression)

	// The vote signature for that height is unchanged and still served.
	unchanged := vote
	resig, _, restamp, err := validator.Sign(ctx, testChainID, VoteToBlock(testChainID, &unchanged))
	require.NoError(t, err)
	require.Equal(t, sig, resig)
	require.True(t, stamp.Equal(restamp))
}

// countingCosigner counts cluster RPCs to a peer so a test can assert a request
// was decided on the leader without consulting any cosigner.
type countingCosigner struct {
	Cosigner
	calls struct {
		sync.Mutex
		nonces, signs int
	}
}

func (c *countingCosigner) GetNonces(ctx context.Context, uuids []uuid.UUID) (CosignerUUIDNoncesMultiple, error) {
	c.calls.Lock()
	c.calls.nonces++
	c.calls.Unlock()
	return c.Cosigner.GetNonces(ctx, uuids)
}

func (c *countingCosigner) SetNoncesAndSign(
	ctx context.Context,
	req CosignerSetNoncesAndSignRequest,
) (*CosignerSignResponse, error) {
	c.calls.Lock()
	c.calls.signs++
	c.calls.Unlock()
	return c.Cosigner.SetNoncesAndSign(ctx, req)
}

func (c *countingCosigner) counts() (nonces, signs int) {
	c.calls.Lock()
	defer c.calls.Unlock()
	return c.calls.nonces, c.calls.signs
}

// A passed-height extension retry must be refused by the leader before nonces
// are drawn or any cosigner is contacted. Deciding it on the leader keeps the
// refusal typed: a peer cosigner's identical refusal crosses the cluster RPC as
// an untyped string, which the privval handler cannot classify and answers by
// dropping the chain node connection — turning a terminal condition into a
// futile retry loop.
func TestThresholdValidatorVoteExtensionStaleHeightDecidedOnLeader(t *testing.T) {
	cosigners, _ := getTestLocalCosigners(t, 2, 2)
	peer := &countingCosigner{Cosigner: cosigners[1]}
	leader := &MockLeader{id: 1}
	validator := NewThresholdValidator(
		cometlog.NewNopLogger(), cosigners[0].config, 2, time.Second, 1,
		cosigners[0], []Cosigner{peer}, leader,
	)
	leader.leader = validator
	t.Cleanup(validator.Stop)
	require.NoError(t, validator.LoadSignStateIfNecessary(testChainID))
	ctx := context.Background()

	vote := voteWithExtension("first")
	_, _, stamp, err := validator.Sign(ctx, testChainID, VoteToBlock(testChainID, &vote))
	require.NoError(t, err)
	vote.Timestamp = stamp

	next := vote
	next.Height++
	_, _, _, err = validator.Sign(ctx, testChainID, VoteToBlock(testChainID, &next))
	require.NoError(t, err)

	noncesBefore, signsBefore := peer.counts()

	// Same vote, changed extension, now a height behind the watermark.
	retry := vote
	retry.Extension = []byte("second")
	_, _, _, err = validator.Sign(ctx, testChainID, VoteToBlock(testChainID, &retry))
	var heightRegression *HeightRegressionError
	require.ErrorAs(t, err, &heightRegression)

	noncesAfter, signsAfter := peer.counts()
	require.Equal(t, noncesBefore, noncesAfter,
		"a stale extension retry must not draw nonces from a cosigner")
	require.Equal(t, signsBefore, signsAfter,
		"a stale extension retry must not reach a cosigner's signer")
}

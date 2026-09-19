package signer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/libs/protoio"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cometrpcjsontypes "github.com/cometbft/cometbft/rpc/jsonrpc/types"
	"github.com/google/uuid"
	"github.com/strangelove-ventures/horcrux/v3/signer/proto"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ PrivValidator = &ThresholdValidator{}

type ThresholdValidator struct {
	config *RuntimeConfig

	threshold int

	grpcTimeout time.Duration

	chainState sync.Map

	// our own cosigner
	myCosigner *LocalCosigner

	// peer cosigners
	peerCosigners Cosigners

	leader Leader

	logger log.Logger

	pendingDiskWG sync.WaitGroup

	maxWaitForSameBlockAttempts int

	cosignerHealth *CosignerHealth

	nonceCache *CosignerNonceCache
}

type ChainSignState struct {
	// stores the last sign state for a block we have fully signed
	// Cached to respond to SignVote requests if we already have a signature
	lastSignState      *SignState
	lastSignStateMutex *sync.Mutex

	// stores the last sign state that we've started progress on
	lastSignStateInitiated      *SignState
	lastSignStateInitiatedMutex *sync.Mutex
}

// NewThresholdValidator creates and returns a new ThresholdValidator
func NewThresholdValidator(
	logger log.Logger,
	config *RuntimeConfig,
	threshold int,
	grpcTimeout time.Duration,
	maxWaitForSameBlockAttempts int,
	myCosigner *LocalCosigner,
	peerCosigners []Cosigner,
	leader Leader,
) *ThresholdValidator {
	allCosigners := make([]Cosigner, len(peerCosigners)+1)
	allCosigners[0] = myCosigner
	copy(allCosigners[1:], peerCosigners)

	for _, cosigner := range peerCosigners {
		logger.Debug("Peer cosigner", "id", cosigner.GetID())
	}

	nc := NewCosignerNonceCache(
		logger,
		allCosigners,
		leader,
		defaultGetNoncesInterval,
		grpcTimeout,
		defaultNonceExpiration,
		uint8(threshold),
		nil,
	)
	return &ThresholdValidator{
		logger:                      logger,
		config:                      config,
		threshold:                   threshold,
		grpcTimeout:                 grpcTimeout,
		maxWaitForSameBlockAttempts: maxWaitForSameBlockAttempts,
		myCosigner:                  myCosigner,
		peerCosigners:               peerCosigners,
		leader:                      leader,
		cosignerHealth:              NewCosignerHealth(logger, peerCosigners, leader),
		nonceCache:                  nc,
	}
}

// Start starts the ThresholdValidator.
func (pv *ThresholdValidator) Start(ctx context.Context) error {
	pv.logger.Info("Starting ThresholdValidator services")

	go pv.cosignerHealth.Start(ctx)

	go pv.nonceCache.Start(ctx)

	go pv.myCosigner.StartNoncePruner(ctx)

	return nil
}

// SaveLastSignedState updates the high watermark height/round/step (HRS) for a completed
// sign process if it is greater than the current high watermark. A mutex is used to avoid concurrent
// state updates. The disk write is scheduled in a separate goroutine which will perform an atomic write.
// pendingDiskWG is used upon termination in pendingDiskWG to ensure all writes have completed.
func (pv *ThresholdValidator) SaveLastSignedState(chainID string, signState SignStateConsensus) error {
	css := pv.mustLoadChainState(chainID)

	css.lastSignStateMutex.Lock()
	defer css.lastSignStateMutex.Unlock()
	return css.lastSignState.Save(signState, &pv.pendingDiskWG)
}

func (pv *ThresholdValidator) mustLoadChainState(chainID string) ChainSignState {
	cs, ok := pv.chainState.Load(chainID)
	if !ok {
		panic(fmt.Errorf("failed to load chain state for %s", chainID))
	}

	css, ok := cs.(ChainSignState)
	if !ok {
		panic(fmt.Errorf("expected: (ChainSignState), actual: (%T)", cs))
	}

	return css
}

// SaveLastSignedStateInitiated updates the high watermark height/round/step (HRS) for an initiated
// sign process if it is greater than the current high watermark. A mutex is used to avoid concurrent
// state updates. The disk write is scheduled in a separate goroutine which will perform an atomic write.
// pendingDiskWG is used upon termination in pendingDiskWG to ensure all writes have completed.
func (pv *ThresholdValidator) SaveLastSignedStateInitiated(
	chainID string,
	block *Block,
) ([]byte, []byte, time.Time, error) {
	css := pv.mustLoadChainState(chainID)

	height, round, step := block.Height, block.Round, block.Step

	err := css.lastSignStateInitiated.Save(NewSignStateConsensus(height, round, step), &pv.pendingDiskWG)
	if err == nil {
		// good to sign
		return nil, nil, time.Time{}, nil
	}

	// There was an error saving the last sign state, so check if there is an existing signature for this block.
	existingSignature, existingVoteExtSignature,
		existingTimestamp, sameBlockErr := pv.getExistingBlockSignature(chainID, block)

	if _, ok := err.(*SameHRSError); !ok {
		if sameBlockErr == nil {
			// existingTimestamp, not the requested one: the signature returned here can
			// be an existing one made over a different timestamp.
			return existingSignature, existingVoteExtSignature, existingTimestamp, nil
		}
		return nil, nil, existingTimestamp, pv.newBeyondBlockError(chainID, block.HRSKey())
	}

	if sameBlockErr == nil {
		if existingSignature != nil {
			// signature already exists for this block. return it.
			return existingSignature, existingVoteExtSignature, existingTimestamp, nil
		}
		// good to sign again
		return nil, nil, time.Time{}, nil
	}

	if _, ok := sameBlockErr.(*StillWaitingForBlockError); !ok {
		// we have an error other than still waiting for block. return error.
		return nil, nil, existingTimestamp, fmt.Errorf(
			"same block error, but we are not still waiting for signature: %w",
			sameBlockErr,
		)
	}

	// the cluster is already in progress signing this block
	// wait for cluster to finish before proceeding

	// intended usage of cond lock prior to cond.Wait().
	// cond.Wait() will unlock cond.L while it blocks waiting, then re-lock when unblocking from
	// the cond.Broadcast().
	css.lastSignState.cond.L.Lock()
	defer css.lastSignState.cond.L.Unlock()
	for i := 0; i < pv.maxWaitForSameBlockAttempts; i++ {
		// block until sign state is saved. It will notify and unblock when block is next signed.
		css.lastSignState.cond.WaitWithTimeout(pv.grpcTimeout)

		// check if HRS exists in cache now
		ssc, ok := css.lastSignState.cache[block.HRSKey()]
		if !ok {
			pv.logger.Debug(
				"Block does not yet exist in cache while waiting for signature",
				"height", height,
				"round", round,
				"step", step,
			)
			continue
		}

		existingSignature, existingVoteExtSignature,
			existingTimestamp, sameBlockErr = pv.compareBlockSignatureAgainstSSC(chainID, block, &ssc)
		if sameBlockErr == nil {
			return existingSignature, existingVoteExtSignature, existingTimestamp, nil
		}
		if _, ok := sameBlockErr.(*StillWaitingForBlockError); !ok {
			return nil, nil, existingTimestamp, fmt.Errorf(
				"same block error in loop, but we are not still waiting for signature: %w",
				sameBlockErr,
			)
		}

		latest := css.lastSignState

		pv.logger.Debug(
			"Waiting for block to be signed",
			"height", height,
			"round", round,
			"step", step,
			"latest_height", latest.Height,
			"latest_round", latest.Round,
			"latest_step", latest.Step,
		)
	}

	return nil, nil, existingTimestamp, fmt.Errorf(
		"exceeded max attempts waiting for block to be signed. height: %d, round: %d, step: %d",
		height, round, step,
	)
}

// notifyBlockSignError will alert any waiting goroutines that an error
// has occurred during signing and a retry can be attempted.
func (pv *ThresholdValidator) notifyBlockSignError(chainID string, hrs HRSKey, signBytes []byte) {
	css := pv.mustLoadChainState(chainID)

	css.lastSignState.mu.Lock()
	css.lastSignState.cache[hrs] = SignStateConsensus{
		Height: hrs.Height,
		Round:  hrs.Round,
		Step:   hrs.Step,
		// empty signature to indicate error
		SignBytes: signBytes,
	}
	css.lastSignState.mu.Unlock()
	css.lastSignState.cond.Broadcast()
}

// Stop safely shuts down the ThresholdValidator.
func (pv *ThresholdValidator) Stop() {
	pv.waitForSignStatesToFlushToDisk()
}

// IsLeader reports whether this cosigner currently leads the signer cluster.
func (pv *ThresholdValidator) IsLeader() bool {
	return pv.leader.IsLeader()
}

// waitForSignStatesToFlushToDisk waits for any sign states to finish writing to disk.
func (pv *ThresholdValidator) waitForSignStatesToFlushToDisk() {
	pv.pendingDiskWG.Wait()

	pv.myCosigner.waitForSignStatesToFlushToDisk()
}

// GetPubKey returns the public key of the validator.
// Implements PrivValidator.
func (pv *ThresholdValidator) GetPubKey(_ context.Context, chainID string) ([]byte, error) {
	pubKey, err := pv.myCosigner.GetPubKey(chainID)
	if err != nil {
		return nil, err
	}
	return pubKey.Bytes(), nil
}

type Block struct {
	Height                 int64
	Round                  int64
	Step                   int8
	SignBytes              []byte
	VoteExtensionSignBytes []byte
	Timestamp              time.Time
}

func (block Block) HRSKey() HRSKey {
	return HRSKey{
		Height: block.Height,
		Round:  block.Round,
		Step:   block.Step,
	}
}

func (block Block) HRSTKey() HRSTKey {
	return HRSTKey{
		Height:    block.Height,
		Round:     block.Round,
		Step:      block.Step,
		Timestamp: block.Timestamp.UnixNano(),
	}
}

func (block Block) ToProto() *proto.Block {
	pb := &proto.Block{
		Height:           block.Height,
		Round:            block.Round,
		Step:             int32(block.Step),
		SignBytes:        block.SignBytes,
		VoteExtSignBytes: block.VoteExtensionSignBytes,
	}
	// UnixNano is undefined outside years 1678-2262; a zero time is carried as
	// the unset sentinel (0) so it survives the round trip as zero instead of
	// reconstructing as a year-1754 garbage timestamp on the other side.
	if !block.Timestamp.IsZero() {
		pb.Timestamp = block.Timestamp.UnixNano()
	}
	return pb
}

func BlockFromProto(block *proto.Block) Block {
	var timestamp time.Time
	if block.Timestamp != 0 {
		timestamp = time.Unix(0, block.Timestamp)
	}
	return Block{
		Height:                 block.Height,
		Round:                  block.Round,
		Step:                   int8(block.Step),
		SignBytes:              block.SignBytes,
		VoteExtensionSignBytes: block.VoteExtSignBytes,
		Timestamp:              timestamp,
	}
}

type BeyondBlockError struct {
	msg string
}

func (e *BeyondBlockError) Error() string { return e.msg }

func (pv *ThresholdValidator) newBeyondBlockError(chainID string, hrs HRSKey) *BeyondBlockError {
	css := pv.mustLoadChainState(chainID)

	lss := css.lastSignStateInitiated
	return &BeyondBlockError{
		msg: fmt.Sprintf("[%s] Progress already started on block %d.%d.%d, skipping %d.%d.%d",
			chainID,
			lss.Height, lss.Round, lss.Step,
			hrs.Height, hrs.Round, hrs.Step,
		),
	}
}

type StillWaitingForBlockError struct {
	msg string
}

func (e *StillWaitingForBlockError) Error() string { return e.msg }

func newStillWaitingForBlockError(chainID string, hrs HRSKey) *StillWaitingForBlockError {
	return &StillWaitingForBlockError{
		msg: fmt.Sprintf("[%s] Still waiting for block %d.%d.%d",
			chainID, hrs.Height, hrs.Round, hrs.Step),
	}
}

type SameBlockError struct {
	msg string
}

func (e *SameBlockError) Error() string { return e.msg }

func newSameBlockError(chainID string, hrs HRSKey) *SameBlockError {
	return &SameBlockError{
		msg: fmt.Sprintf("[%s] Same block: %d.%d.%d",
			chainID, hrs.Height, hrs.Round, hrs.Step),
	}
}

func (pv *ThresholdValidator) LoadSignStateIfNecessary(chainID string) error {
	if err := ValidateChainID(chainID); err != nil {
		return err
	}
	if _, ok := pv.chainState.Load(chainID); ok {
		return nil
	}

	signState, err := LoadOrCreateSignState(pv.config.PrivValStateFile(chainID))
	if err != nil {
		return err
	}

	lastSignStateInitiated := signState.FreshCache()
	lastSignStateInitiated.filePath = os.DevNull

	pv.chainState.Store(chainID, ChainSignState{
		lastSignState:          signState,
		lastSignStateInitiated: lastSignStateInitiated,

		lastSignStateMutex:          &sync.Mutex{},
		lastSignStateInitiatedMutex: &sync.Mutex{},
	})

	return pv.myCosigner.LoadSignStateIfNecessary(chainID)
}

// getExistingBlockSignature returns the existing block signature and no error if the signature is valid for the block.
// It returns nil signature and nil error if there is no signature and it's okay to sign (fresh or again).
// It returns an error if we have already signed a greater block, or if we are still waiting for in in-progress sign.
func (pv *ThresholdValidator) getExistingBlockSignature(
	chainID string,
	block *Block,
) ([]byte, []byte, time.Time, error) {
	css := pv.mustLoadChainState(chainID)

	latestBlock, existingSignature := css.lastSignState.GetFromCache(block.HRSKey())
	if existingSignature != nil {
		// signature exists in cache, so compare against that
		return pv.compareBlockSignatureAgainstSSC(chainID, block, existingSignature)
	}

	// signature does not exist in cache, so compare against latest signed block.
	return nil, nil, block.Timestamp, pv.compareBlockSignatureAgainstHRS(chainID, block, latestBlock)
}

// compareBlockSignatureAgainstSSC compares a block's HRS against a cached signature.
//
// If the existing signature is for a greater HRS than the block, we are already beyond
// the requested HRS, so we can error and move on.
//
// If the existing signature is for a lesser HRS than the block, then we can return
// a stillWaitingForBlock error to continue waiting for the HRS to be signed.
//
// If the HRS of the existing signature and the block are the same, we return the existing signature
// if the block sign request is for a proposal or if the bytes to sign are identical.
func (pv *ThresholdValidator) compareBlockSignatureAgainstSSC(
	chainID string,
	block *Block,
	existingSignature *SignStateConsensus,
) ([]byte, []byte, time.Time, error) {
	stamp, signBytes := block.Timestamp, block.SignBytes

	if err := pv.compareBlockSignatureAgainstHRS(chainID, block, existingSignature.HRSKey()); err != nil {
		if _, ok := err.(*SameBlockError); !ok {
			return nil, nil, stamp, err
		}
	}

	// An existing signature is never paired with the requested timestamp: the chain
	// node stamps its message with whatever the signer returns, so the timestamp has
	// to be the one the existing signature was made over. They are the same when the
	// payloads are identical, and differ for the two cases below.
	existingStamp, err := signBytesTimestamp(existingSignature.Step, existingSignature.SignBytes)
	if err != nil {
		return nil, nil, stamp, err
	}

	// If a proposal has already been signed for this HRS, or the sign payload is identical, return the existing signature.
	if block.Step == stepPropose || bytes.Equal(signBytes, existingSignature.SignBytes) {
		return existingSignature.Signature, existingSignature.VoteExtensionSignature, existingStamp, nil
	}

	// If there is a difference in the existing signature payload other than timestamp, return that error.
	if err := existingSignature.OnlyDifferByTimestamp(signBytes); err != nil {
		return nil, nil, stamp, err
	}

	// Only differ by timestamp: return the existing signature instead of signing
	// again. Signing again yields a second, equally valid signature over the same
	// height/round/step, which every peer that already holds the first one rejects
	// as ErrVoteNonDeterministicSignature. This mirrors what a chain node's own
	// file-based signer does with its state file (CometBFT FilePV.signVote /
	// gno.land tm2 PrivValidator.SignVote): reuse the last signature and its timestamp.
	return existingSignature.Signature, existingSignature.VoteExtensionSignature, existingStamp, nil
}

// signBytesTimestamp returns the timestamp a set of canonical sign bytes was signed over.
func signBytesTimestamp(step int8, signBytes []byte) (time.Time, error) {
	if step == stepPropose {
		var proposal cometproto.CanonicalProposal
		if err := protoio.UnmarshalDelimited(signBytes, &proposal); err != nil {
			return time.Time{}, newUnmarshalError("signBytes", "proposal", err)
		}

		return proposal.Timestamp, nil
	}

	var vote cometproto.CanonicalVote
	if err := protoio.UnmarshalDelimited(signBytes, &vote); err != nil {
		return time.Time{}, newUnmarshalError("signBytes", "vote", err)
	}

	return vote.Timestamp, nil
}

// compareBlockSignatureAgainstHRS returns a BeyondBlockError if the hrs is greater than the
// block. It returns a StillWaitingForBlockError if the hrs is less than the block. If returns nil if the hrs is
// equal to the block.
func (pv *ThresholdValidator) compareBlockSignatureAgainstHRS(
	chainID string,
	block *Block,
	hrs HRSKey,
) error {
	blockHRS := block.HRSKey()

	if hrs.GreaterThan(blockHRS) {
		return pv.newBeyondBlockError(chainID, blockHRS)
	}

	if hrs == blockHRS {
		return newSameBlockError(chainID, blockHRS)
	}

	return newStillWaitingForBlockError(chainID, blockHRS)
}

func (pv *ThresholdValidator) getNoncesFallback(
	ctx context.Context,
	count int,
) (*CosignersAndNonces, error) {
	drainedNonceCache.Inc()
	totalDrainedNonceCache.Inc()

	// The workers below end when their cosigner call returns; bounding the calls
	// here makes that self-contained instead of relying on a deadline further up
	// the request path.
	ctx, cancel := context.WithTimeout(ctx, pv.grpcTimeout)
	defer cancel()

	var mu sync.Mutex

	uuids := make([]uuid.UUID, count)
	for i := 0; i < count; i++ {
		uuids[i] = uuid.New()
	}

	allCosigners := make([]Cosigner, len(pv.peerCosigners)+1)
	allCosigners[0] = pv.myCosigner
	copy(allCosigners[1:], pv.peerCosigners)

	var thresholdNonces CosignersAndNonces
	// Closed under mu by whichever cosigner completes the threshold. A channel
	// rather than a WaitGroup: a count that errors can leave short would pin a
	// waiter goroutine forever, leaking one per failed fallback — the worker
	// goroutines themselves always end when their bounded cosigner call returns.
	// An unreachable threshold (misconfiguration) never closes the channel and
	// the fallback times out, instead of returning an empty nonce set.
	thresholdReached := make(chan struct{})

	for _, c := range allCosigners {
		go pv.waitForPeerNonces(ctx, uuids, c, thresholdReached, &thresholdNonces, &mu)
	}

	// Wait for threshold cosigners to be complete
	// A Cosigner will either respond in time, or be cancelled with timeout
	select {
	case <-thresholdReached:
		return &thresholdNonces, nil
	case <-time.After(pv.grpcTimeout):
		return nil, errors.New("timed out waiting for ephemeral shares")
	}
}

type CosignersAndNonces struct {
	Cosigners Cosigners
	Nonces    CosignerUUIDNoncesMultiple
}

func (pv *ThresholdValidator) waitForPeerNonces(
	ctx context.Context,
	uuids []uuid.UUID,
	peer Cosigner,
	thresholdReached chan<- struct{},
	thresholdNonces *CosignersAndNonces,
	mu sync.Locker,
) {
	peerStartTime := time.Now()

	peerNonces, err := peer.GetNonces(ctx, uuids)
	if err != nil {
		missedNonces.WithLabelValues(peer.GetAddress()).Inc()
		totalMissedNonces.WithLabelValues(peer.GetAddress()).Inc()

		pv.logger.Error("Error getting nonces", "cosigner", peer.GetID(), "err", err)
		return
	}

	missedNonces.WithLabelValues(peer.GetAddress()).Set(0)
	timedCosignerNonceLag.WithLabelValues(peer.GetAddress()).Observe(time.Since(peerStartTime).Seconds())

	mu.Lock()
	defer mu.Unlock()
	// A late success past the threshold must not touch the result the caller may
	// already be reading, and must not close the channel twice.
	if len(thresholdNonces.Cosigners) >= pv.threshold {
		return
	}
	thresholdNonces.Cosigners = append(thresholdNonces.Cosigners, peer)
	for _, n := range peerNonces {
		var found bool
		for _, nn := range thresholdNonces.Nonces {
			if n.UUID == nn.UUID {
				nn.Nonces = append(nn.Nonces, n.Nonces...)
				found = true
				break
			}
		}
		if !found {
			thresholdNonces.Nonces = append(thresholdNonces.Nonces, n)
		}
	}
	if len(thresholdNonces.Cosigners) == pv.threshold {
		close(thresholdReached)
	}
}

func (pv *ThresholdValidator) proxyIfNecessary(
	ctx context.Context,
	chainID string,
	block Block,
) (bool, []byte, []byte, time.Time, error) {
	height, round, step, stamp := block.Height, block.Round, block.Step, block.Timestamp

	if pv.leader.IsLeader() {
		return false, nil, nil, time.Time{}, nil
	}

	leader := pv.leader.GetLeader()

	// TODO is there a better way than to poll during leader election?
	for i := 0; i < 500 && leader == -1; i++ {
		time.Sleep(10 * time.Millisecond)
		leader = pv.leader.GetLeader()
	}

	if leader == -1 {
		totalRaftLeaderElectionTimeout.Inc()
		return true, nil, nil, stamp, fmt.Errorf("timed out waiting for raft leader")
	}

	if leader == pv.myCosigner.GetID() {
		return false, nil, nil, time.Time{}, nil
	}

	pv.logger.Debug("I am not the leader. Proxying request to the leader",
		"chain_id", chainID,
		"height", height,
		"round", round,
		"step", step,
	)
	totalNotRaftLeader.Inc()

	cosignerLeader := pv.peerCosigners.GetByID(leader)
	if cosignerLeader == nil {
		return true, nil, nil, stamp, fmt.Errorf("failed to find cosigner with id %d", leader)
	}

	signRes, err := cosignerLeader.(*RemoteCosigner).Sign(ctx, CosignerSignBlockRequest{
		ChainID: chainID,
		Block:   &block,
	})
	if err != nil {
		if _, ok := err.(*cometrpcjsontypes.RPCError); ok {
			rpcErrUnwrapped := err.(*cometrpcjsontypes.RPCError).Data
			// Need to return BeyondBlockError after proxy since the error type will be lost over RPC
			if len(rpcErrUnwrapped) > 33 && rpcErrUnwrapped[:33] == "Progress already started on block" {
				return true, nil, nil, stamp, &BeyondBlockError{msg: rpcErrUnwrapped}
			}
		}
		return true, nil, nil, stamp, err
	}
	// The leader may have answered from an existing signature for this HRS, which
	// is made over its timestamp, not ours. Return the leader's timestamp so the
	// chain node stamps the vote the signature actually covers.
	return true, signRes.Signature, signRes.VoteExtensionSignature, signRes.Timestamp, nil
}

// voteExtensionNonces draws the two nonce rounds a vote extension retry needs,
// preferring the prepared cache. Going straight to getNoncesFallback would make
// every retry look like a drained cache to the operator's metrics.
func (pv *ThresholdValidator) voteExtensionNonces(ctx context.Context) (*CosignersAndNonces, error) {
	fastest := pv.cosignerHealth.GetFastest()
	if len(fastest) >= pv.threshold-1 {
		cosigners := make(Cosigners, pv.threshold)
		cosigners[0] = pv.myCosigner
		copy(cosigners[1:], fastest[:pv.threshold-1])

		if voteNonces, err := pv.nonceCache.GetNonces(cosigners); err == nil {
			// The vote round is spent even if the extension round is missing: a
			// nonce must never be offered twice.
			if extNonces, err := pv.nonceCache.GetNonces(cosigners); err == nil {
				return &CosignersAndNonces{
					Cosigners: cosigners,
					Nonces:    CosignerUUIDNoncesMultiple{voteNonces, extNonces},
				}, nil
			}
		}
	}

	return pv.getNoncesFallback(ctx, 2)
}

// signVoteExtension signs an extension for a vote whose full signature is already
// cached. The existing RPC carries the original vote as well so each cosigner
// still checks its signing state before signing the extension. Only the
// extension shares are combined: the vote already has its full signature, and
// the fresh vote shares each cosigner produces alongside are discarded.
// An error here must not replace the completed vote with a failed-sign marker.
func (pv *ThresholdValidator) signVoteExtension(
	ctx context.Context,
	chainID string,
	block Block,
	stamp time.Time,
) ([]byte, error) {
	var vote cometproto.CanonicalVote
	if err := protoio.UnmarshalDelimited(block.SignBytes, &vote); err != nil {
		return nil, newUnmarshalError("signBytes", "vote", err)
	}
	vote.Timestamp = stamp
	signBytes, err := protoio.MarshalDelimited(&vote)
	if err != nil {
		return nil, fmt.Errorf("marshalling cached vote: %w", err)
	}

	// Keep distinct nonce rounds for the vote and extension. A cosigner that
	// missed the original vote may need to sign it before it can sign the extension.
	// Its vote share is discarded; the caller keeps the cached full vote signature.
	nonces, err := pv.voteExtensionNonces(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting vote extension nonces: %w", err)
	}
	// A peer that answers with fewer rounds than requested must not index out of
	// range: a panic here takes down a signer that is otherwise healthy.
	if len(nonces.Nonces) < 2 {
		return nil, fmt.Errorf("got %d nonce rounds for vote extension, need 2", len(nonces.Nonces))
	}

	shares := make([]PartialSignature, len(nonces.Cosigners))
	var eg errgroup.Group
	for i, cosigner := range nonces.Cosigners {
		eg.Go(func() error {
			signCtx, cancel := context.WithTimeout(ctx, pv.grpcTimeout)
			defer cancel()
			res, err := cosigner.SetNoncesAndSign(signCtx, CosignerSetNoncesAndSignRequest{
				ChainID: chainID,
				HRST: HRSTKey{
					Height: block.Height, Round: block.Round, Step: block.Step, Timestamp: stamp.UnixNano(),
				},
				SignBytes:              signBytes,
				Nonces:                 nonces.Nonces[0].For(cosigner.GetID()),
				VoteExtensionSignBytes: block.VoteExtensionSignBytes,
				VoteExtensionNonces:    nonces.Nonces[1].For(cosigner.GetID()),
			})
			if err != nil {
				return fmt.Errorf("cosigner %d signing vote extension: %w", cosigner.GetID(), err)
			}
			if len(res.VoteExtensionSignature) == 0 {
				return fmt.Errorf("cosigner %d returned no vote extension signature", cosigner.GetID())
			}
			shares[i] = PartialSignature{ID: cosigner.GetID(), Signature: res.VoteExtensionSignature}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}
	signature, err := pv.myCosigner.CombineSignatures(chainID, shares)
	if err != nil {
		return nil, fmt.Errorf("combining vote extension signatures: %w", err)
	}
	if !pv.myCosigner.VerifySignature(chainID, block.VoteExtensionSignBytes, signature) {
		return nil, errors.New("combined signature for vote extension is not valid")
	}
	return signature, nil
}

func (pv *ThresholdValidator) Sign(
	ctx context.Context,
	chainID string,
	block Block,
) ([]byte, []byte, time.Time, error) {
	height, round, step, stamp := block.Height, block.Round, block.Step, block.Timestamp
	signBytes, voteExtensionSignBytes := block.SignBytes, block.VoteExtensionSignBytes

	log := pv.logger.With(
		"chain_id", chainID,
		"height", height,
		"round", round,
		"type", signType(step),
	)

	if err := pv.LoadSignStateIfNecessary(chainID); err != nil {
		return nil, nil, stamp, err
	}

	// Only the leader can execute this function. Followers can handle the requests,
	// but they just need to proxy the request to the raft leader
	isProxied, proxySig, proxyVoteExtSig, proxyStamp, err := pv.proxyIfNecessary(ctx, chainID, block)
	if isProxied {
		return proxySig, proxyVoteExtSig, proxyStamp, err
	}

	totalRaftLeader.Inc()

	log.Debug("I am the leader. Managing the sign process for this block")

	timeStartSignBlock := time.Now()

	hrst := HRSTKey{
		Height:    height,
		Round:     round,
		Step:      step,
		Timestamp: stamp.UnixNano(),
	}

	// Keep track of the last block that we began the signing process for. Only allow one attempt per block
	existingSignature, existingVoteExtSig, existingTimestamp, err := pv.SaveLastSignedStateInitiated(chainID, &block)
	if err != nil {
		return nil, nil, stamp, fmt.Errorf("error saving last sign state initiated: %w", err)
	}
	if existingSignature != nil {
		log.Debug("Returning existing signature", "signature", fmt.Sprintf("%x", existingSignature))
		_, hasVoteExtensions, err := verifySignPayload(chainID, signBytes, voteExtensionSignBytes)
		if err != nil {
			return nil, nil, stamp, fmt.Errorf("failed to verify payload: %w", err)
		}
		if !hasVoteExtensions {
			return existingSignature, nil, existingTimestamp, nil
		}
		// The vote cache does not identify the extension. Reuse its extension
		// signature only if it verifies against the extension in this request.
		if !pv.myCosigner.VerifySignature(chainID, voteExtensionSignBytes, existingVoteExtSig) {
			// Decide the height bound here, before nonces are drawn or cosigners
			// contacted. Each cosigner enforces the same bound, but a peer's
			// refusal crosses the cluster RPC as an untyped string that the
			// privval handler cannot classify as a refusal, so it would drop the
			// chain node connection for a condition no retry can change.
			latest := pv.mustLoadChainState(chainID).lastSignState.LatestHRS()
			if block.Height != latest.Height {
				return nil, nil, stamp, newHeightRegressionError(block.Height, latest.Height)
			}
			log.Debug("Signing a changed vote extension for an already signed vote")
			totalVoteExtensionResigns.WithLabelValues(chainID).Inc()
			existingVoteExtSig, err = pv.signVoteExtension(ctx, chainID, block, existingTimestamp)
			if err != nil {
				log.Error("Failed to sign changed vote extension", "err", err.Error())
				return nil, nil, stamp, err
			}
		}
		return existingSignature, existingVoteExtSig, existingTimestamp, nil
	}

	numPeers := len(pv.peerCosigners)
	total := uint8(numPeers + 1)

	peerStartTime := time.Now()

	cosignersOrderedByFastest := pv.cosignerHealth.GetFastest()
	cosignersForThisBlock := make([]Cosigner, pv.threshold)
	cosignersForThisBlock[0] = pv.myCosigner
	copy(cosignersForThisBlock[1:], cosignersOrderedByFastest[:pv.threshold-1])

	var dontIterateFastestCosigners bool

	_, hasVoteExtensions, err := verifySignPayload(chainID, signBytes, voteExtensionSignBytes)
	if err != nil {
		pv.notifyBlockSignError(chainID, block.HRSKey(), signBytes)
		return nil, nil, stamp, fmt.Errorf("failed to verify payload: %w", err)
	}

	count := 1
	if hasVoteExtensions {
		count = 2
	}

	var voteExtNonces *CosignerUUIDNonces
	nonces, err := pv.nonceCache.GetNonces(cosignersForThisBlock)
	if err != nil {
		var fallbackRes *CosignersAndNonces
		var fallbackErr error

		fallbackRes, fallbackErr = pv.getNoncesFallback(ctx, count)
		if fallbackErr != nil {
			pv.notifyBlockSignError(chainID, block.HRSKey(), signBytes)
			return nil, nil, stamp, fmt.Errorf("failed to get nonces: %w", errors.Join(err, fallbackErr))
		}

		cosignersForThisBlock = fallbackRes.Cosigners
		nonces = fallbackRes.Nonces[0]
		if hasVoteExtensions {
			voteExtNonces = fallbackRes.Nonces[1]
		}
		dontIterateFastestCosigners = true
	} else {
		drainedNonceCache.Set(0)
	}

	if err == nil && hasVoteExtensions {
		voteExtNonces, err = pv.nonceCache.GetNonces(cosignersForThisBlock)
		if err != nil {

			u := uuid.New()
			var eg errgroup.Group
			var mu sync.Mutex
			for _, c := range cosignersForThisBlock {
				c := c
				eg.Go(func() error {
					nonces, err := c.GetNonces(ctx, []uuid.UUID{u})
					if err != nil {
						return err
					}
					mu.Lock()
					defer mu.Unlock()
					if voteExtNonces == nil {
						voteExtNonces = nonces[0]
					} else {
						voteExtNonces.Nonces = append(voteExtNonces.Nonces, nonces[0].Nonces...)
					}
					return nil
				})
			}

			if fallbackErr := eg.Wait(); fallbackErr != nil {
				pv.notifyBlockSignError(chainID, block.HRSKey(), signBytes)
				return nil, nil, stamp, fmt.Errorf("failed to get nonces for vote extensions: %w", errors.Join(err, fallbackErr))
			}
		}
	}

	nextFastestCosignerIndex := pv.threshold - 1
	var nextFastestCosignerIndexMu sync.Mutex
	getNextFastestCosigner := func() Cosigner {
		nextFastestCosignerIndexMu.Lock()
		defer nextFastestCosignerIndexMu.Unlock()
		if nextFastestCosignerIndex >= len(cosignersOrderedByFastest) {
			return nil
		}
		cosigner := cosignersOrderedByFastest[nextFastestCosignerIndex]
		nextFastestCosignerIndex++
		return cosigner
	}

	timedSignBlockThresholdLag.Observe(time.Since(timeStartSignBlock).Seconds())

	for _, peer := range pv.peerCosigners {
		missedNonces.WithLabelValues(peer.GetAddress()).Set(0)
		timedCosignerNonceLag.WithLabelValues(peer.GetAddress()).Observe(time.Since(peerStartTime).Seconds())
	}

	cosignersForThisBlockInt := make([]int, len(cosignersForThisBlock))

	for i, cosigner := range cosignersForThisBlock {
		cosignersForThisBlockInt[i] = cosigner.GetID()
	}

	// destination for share signatures
	shareSignatures := make([][]byte, total)
	voteExtShareSignatures := make([][]byte, total)

	var eg errgroup.Group
	for _, cosigner := range cosignersForThisBlock {
		cosigner := cosigner
		eg.Go(func() error {
			for cosigner != nil {
				signCtx, cancel := context.WithTimeout(ctx, pv.grpcTimeout)
				defer cancel()

				peerStartTime := time.Now()

				sigReq := CosignerSetNoncesAndSignRequest{
					ChainID:   chainID,
					Nonces:    nonces.For(cosigner.GetID()),
					HRST:      hrst,
					SignBytes: signBytes,
				}

				if voteExtNonces != nil {
					sigReq.VoteExtensionSignBytes = voteExtensionSignBytes
					sigReq.VoteExtensionNonces = voteExtNonces.For(cosigner.GetID())
				}

				// set peerNonces and sign in single rpc call.
				sigRes, err := cosigner.SetNoncesAndSign(signCtx, sigReq)
				if err != nil {
					log.Error(
						"Cosigner failed to set nonces and sign",
						"cosigner", cosigner.GetID(),
						"err", err.Error(),
					)

					if strings.Contains(err.Error(), errUnexpectedState) {
						pv.nonceCache.ClearNonces(cosigner)
					}

					if cosigner.GetID() == pv.myCosigner.GetID() {
						return err
					}

					if c := status.Code(err); c == codes.DeadlineExceeded || c == codes.NotFound || c == codes.Unavailable {
						pv.cosignerHealth.MarkUnhealthy(cosigner)
						pv.nonceCache.ClearNonces(cosigner)
					}

					if dontIterateFastestCosigners {
						cosigner = nil
						continue
					}

					// this will only work if the next cosigner has the nonces we've already decided to use for this block
					// otherwise the sign attempt will fail
					cosigner = getNextFastestCosigner()
					continue
				}

				if cosigner != pv.myCosigner {
					timedCosignerSignLag.WithLabelValues(cosigner.GetAddress()).Observe(time.Since(peerStartTime).Seconds())
				}
				shareSignatures[cosigner.GetID()-1] = sigRes.Signature
				voteExtShareSignatures[cosigner.GetID()-1] = sigRes.VoteExtensionSignature

				return nil
			}
			return fmt.Errorf("no cosigners available to sign")
		})
	}

	if err := eg.Wait(); err != nil {
		pv.notifyBlockSignError(chainID, block.HRSKey(), signBytes)
		return nil, nil, stamp, fmt.Errorf("error from cosigner(s): %s", err)
	}

	timedSignBlockCosignerLag.Observe(time.Since(timeStartSignBlock).Seconds())

	// collect all valid responses into array of partial signatures
	shareSigs := make([]PartialSignature, 0, pv.threshold)
	for idx, shareSig := range shareSignatures {
		if len(shareSig) == 0 {
			continue
		}

		sig := make([]byte, len(shareSig))
		copy(sig, shareSig)

		// we are ok to use the share signatures - complete boolean
		// prevents future concurrent access
		shareSigs = append(shareSigs, PartialSignature{
			ID:        idx + 1,
			Signature: sig,
		})
	}

	if len(shareSigs) < pv.threshold {
		totalInsufficientCosigners.Inc()
		pv.notifyBlockSignError(chainID, block.HRSKey(), signBytes)
		return nil, nil, stamp, errors.New("not enough cosigners")
	}

	// assemble into final signature
	signature, err := pv.myCosigner.CombineSignatures(chainID, shareSigs)
	if err != nil {
		pv.notifyBlockSignError(chainID, block.HRSKey(), signBytes)
		return nil, nil, stamp, fmt.Errorf("error combining signatures: %w", err)
	}

	// verify the combined signature before saving to watermark
	if !pv.myCosigner.VerifySignature(chainID, signBytes, signature) {
		totalInvalidSignature.Inc()

		pv.notifyBlockSignError(chainID, block.HRSKey(), signBytes)
		return nil, nil, stamp, errors.New("combined signature is not valid")
	}

	var voteExtSig []byte

	if hasVoteExtensions {
		// collect all valid responses into array of partial signatures
		voteExtShareSigs := make([]PartialSignature, 0, pv.threshold)
		for idx, shareSig := range voteExtShareSignatures {
			if len(shareSig) == 0 {
				continue
			}

			sig := make([]byte, len(shareSig))
			copy(sig, shareSig)

			// we are ok to use the share signatures - complete boolean
			// prevents future concurrent access
			voteExtShareSigs = append(voteExtShareSigs, PartialSignature{
				ID:        idx + 1,
				Signature: sig,
			})
		}

		if len(voteExtShareSigs) < pv.threshold {
			totalInsufficientCosigners.Inc()
			pv.notifyBlockSignError(chainID, block.HRSKey(), signBytes)
			return nil, nil, stamp, errors.New("not enough cosigners for vote extension")
		}

		// assemble into final signature
		voteExtSig, err = pv.myCosigner.CombineSignatures(chainID, voteExtShareSigs)
		if err != nil {
			pv.notifyBlockSignError(chainID, block.HRSKey(), signBytes)
			return nil, nil, stamp, fmt.Errorf("error combining vote extension signatures: %w", err)
		}

		// verify the combined signature before saving to watermark
		if !pv.myCosigner.VerifySignature(chainID, voteExtensionSignBytes, voteExtSig) {
			totalInvalidSignature.Inc()

			pv.notifyBlockSignError(chainID, block.HRSKey(), signBytes)
			return nil, nil, stamp, errors.New("combined signature for vote extension is not valid")
		}
	}

	newLss := ChainSignStateConsensus{
		ChainID: chainID,
		SignStateConsensus: SignStateConsensus{
			Height:                 height,
			Round:                  round,
			Step:                   step,
			Signature:              signature,
			SignBytes:              signBytes,
			VoteExtensionSignature: voteExtSig,
		},
	}

	css := pv.mustLoadChainState(chainID)

	// Err will be present if newLss is not above high watermark
	css.lastSignStateMutex.Lock()
	err = css.lastSignState.Save(newLss.SignStateConsensus, &pv.pendingDiskWG)
	css.lastSignStateMutex.Unlock()
	if err != nil {
		if _, isSameHRSError := err.(*SameHRSError); !isSameHRSError {

			pv.notifyBlockSignError(chainID, block.HRSKey(), signBytes)
			return nil, nil, stamp, fmt.Errorf("error saving last sign state: %w", err)
		}
	}

	// Emit last signed state to cluster
	err = pv.leader.ShareSigned(newLss)
	if err != nil {
		// this is not required for double sign protection, so we don't need to return an error here.
		// this is only an additional mechanism that will catch double signs earlier in the sign process.
		log.Error("Error emitting LSS", err.Error())
	}

	timeSignBlock := time.Since(timeStartSignBlock)
	timeSignBlockSec := timeSignBlock.Seconds()
	timedSignBlockLag.Observe(timeSignBlockSec)

	log.Info(
		"Signed",
		"duration_ms", float64(timeSignBlock.Microseconds())/1000,
	)

	return signature, voteExtSig, stamp, nil
}

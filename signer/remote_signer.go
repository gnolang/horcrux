package signer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometcryptoencoding "github.com/cometbft/cometbft/crypto/encoding"
	cometlog "github.com/cometbft/cometbft/libs/log"
	cometnet "github.com/cometbft/cometbft/libs/net"
	cometservice "github.com/cometbft/cometbft/libs/service"
	cometp2pconn "github.com/cometbft/cometbft/p2p/conn"
	cometprotocrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	cometprotoprivval "github.com/cometbft/cometbft/proto/tendermint/privval"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

const (
	connRetrySec = 2

	// leaderCheckInterval is how often a leadership-gated signer re-evaluates
	// raft leadership, both while parked as a follower and while holding a
	// connection as the leader. It must be well under the chain node's
	// ~3-second connection-accept window so a new leader dials in time.
	leaderCheckInterval = 250 * time.Millisecond
)

const (
	// defaultSignRequestTimeout bounds how long a sign request may run before the
	// signer abandons it and drops the chain node connection instead of
	// answering. It is deliberately NOT answered with a RemoteSignerError: a
	// strict node (tm2) treats that as a terminal signer refusal and never
	// retries it, while a dropped connection is a transport error its retry
	// budget handles (see signRefusal). The value must be shorter than the chain
	// node's priv-validator read/write timeout (CometBFT/tm2 default 5s) and
	// longer than the per-cosigner grpcTimeout so a normal sign round completes.
	// The budget starts when the request handler runs — request read/decode and
	// the node↔signer round trip are outside it — so the 1.5s headroom against
	// tm2's 5s assumes the signer and node share a low-latency network (LAN).
	defaultSignRequestTimeout = 3500 * time.Millisecond

	// defaultChainNodeReadTimeout / defaultChainNodeWriteTimeout bound reads and
	// writes on the chain node connection so a dead or half-open socket is
	// detected and the signer re-dials while still leader. The read timeout must
	// exceed the chain node's ping interval (tm2 pings at ~2/3 of its read/write
	// timeout) so idle periods do not trip it.
	defaultChainNodeReadTimeout  = 10 * time.Second
	defaultChainNodeWriteTimeout = 10 * time.Second
)

// PrivValidator is a wrapper for tendermint PrivValidator,
// with additional Stop method for safe shutdown.
type PrivValidator interface {
	Sign(ctx context.Context, chainID string, block Block) ([]byte, []byte, time.Time, error)
	GetPubKey(ctx context.Context, chainID string) ([]byte, error)
	Stop()
}

// ReconnRemoteSigner dials using its dialer and responds to any
// signature requests using its privVal.
type ReconnRemoteSigner struct {
	cometservice.BaseService

	address string
	privKey cometcryptoed25519.PrivKey
	// nodePubKey is the connection public key the chain node must present, or nil
	// when the node is not authenticated.
	nodePubKey cometcryptoed25519.PubKey
	privVal    PrivValidator

	dialer net.Dialer

	maxReadSize int

	// isLeader, when non-nil, gates the connection on cluster leadership: the
	// signer only dials while it reports true and releases the connection when
	// it turns false, so a chain node holding a single signer slot always talks
	// to the current raft leader. Nil means always connect.
	isLeader func() bool

	// Timeouts are set once at construction and only read afterward. See the
	// default* consts for the rationale.
	signRequestTimeout    time.Duration
	chainNodeReadTimeout  time.Duration
	chainNodeWriteTimeout time.Duration

	// cancel ends the request loop's context on OnStop, aborting in-flight sign
	// waits, dials and leadership parks.
	cancel context.CancelFunc
}

// NewReconnRemoteSigner return a ReconnRemoteSigner that will dial using the given
// dialer and respond to any signature requests over the connection
// using the given privVal. connAuth optionally authenticates either end of that
// connection. isLeader, when non-nil, restricts the connection to the current
// cluster leader (see the field doc).
//
// If the connection is broken, the ReconnRemoteSigner will attempt to reconnect.
func NewReconnRemoteSigner(
	address string,
	logger cometlog.Logger,
	privVal PrivValidator,
	dialer net.Dialer,
	maxReadSize int,
	connAuth ConnAuth,
	isLeader func() bool,
) *ReconnRemoteSigner {
	privKey := connAuth.PrivKey
	if privKey == nil {
		privKey = cometcryptoed25519.GenPrivKey()
	}

	rs := &ReconnRemoteSigner{
		address:               address,
		privVal:               privVal,
		dialer:                dialer,
		privKey:               privKey,
		nodePubKey:            connAuth.NodePubKey,
		maxReadSize:           maxReadSize,
		isLeader:              isLeader,
		signRequestTimeout:    defaultSignRequestTimeout,
		chainNodeReadTimeout:  defaultChainNodeReadTimeout,
		chainNodeWriteTimeout: defaultChainNodeWriteTimeout,
	}

	rs.BaseService = *cometservice.NewBaseService(logger, "RemoteSigner", rs)
	return rs
}

// OnStart implements cmn.Service.
func (rs *ReconnRemoteSigner) OnStart() error {
	ctx, cancel := context.WithCancel(context.Background())
	rs.cancel = cancel
	go rs.loop(ctx)
	return nil
}

// OnStop implements cmn.Service. Cancelling the loop context first aborts an
// in-flight sign wait and any dial or leadership park, so shutdown does not
// hang behind them.
func (rs *ReconnRemoteSigner) OnStop() {
	if rs.cancel != nil {
		rs.cancel()
	}
	rs.privVal.Stop()
}

func (rs *ReconnRemoteSigner) establishConnection(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, connRetrySec*time.Second)
	defer cancel()

	proto, address := cometnet.ProtocolAndAddress(rs.address)
	netConn, err := rs.dialer.DialContext(ctx, proto, address)
	if err != nil {
		return nil, fmt.Errorf("dial error: %w", err)
	}

	conn, err := cometp2pconn.MakeSecretConnection(netConn, rs.privKey)
	if err != nil {
		netConn.Close()
		return nil, fmt.Errorf("secret connection error: %w", err)
	}

	if err := verifyNodePubKey(rs.nodePubKey, conn.RemotePubKey()); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// main loop for ReconnRemoteSigner
func (rs *ReconnRemoteSigner) loop(ctx context.Context) {
	var conn net.Conn
	// watchStop stops the leadership watcher tied to the current connection.
	// Non-nil exactly while a watcher is running.
	var watchStop chan struct{}

	dropConn := func() {
		rs.closeConn(conn)
		conn = nil
		if watchStop != nil {
			close(watchStop)
			watchStop = nil
		}
	}

	for {
		if !rs.IsRunning() {
			dropConn()
			return
		}

		// A leadership-gated follower parks here without dialing, so the chain
		// node's single signer slot stays free for the current leader.
		if conn == nil && !rs.waitForLeadership(ctx) {
			return
		}

		retries := 0
		for conn == nil {
			var err error
			timer := time.NewTimer(connRetrySec * time.Second)
			conn, err = rs.establishConnection(ctx)
			if err == nil {
				sentryConnectTries.WithLabelValues(rs.address).Set(0)
				timer.Stop()
				rs.Logger.Info("Connected to Sentry", "address", rs.address)
				break
			}

			sentryConnectTries.WithLabelValues(rs.address).Add(1)
			totalSentryConnectTries.WithLabelValues(rs.address).Inc()
			retries++
			rs.Logger.Error(
				"Error establishing connection, will retry",
				"sleep (s)", connRetrySec,
				"address", rs.address,
				"attempt", retries,
				"err", err,
			)
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				continue
			}
		}

		// since dialing can take time, we check running again
		if !rs.IsRunning() {
			dropConn()
			return
		}

		if rs.isLeader != nil && watchStop == nil {
			watchStop = make(chan struct{})
			go rs.releaseConnOnLeadershipLoss(conn, watchStop)
		}

		// Bound the read so a dead or half-open chain node socket is detected and
		// the connection re-dialed while still leader, instead of blocking here
		// forever. The chain node pings well within this window, so a healthy idle
		// connection never trips it.
		if err := conn.SetReadDeadline(time.Now().Add(rs.chainNodeReadTimeout)); err != nil {
			rs.Logger.Error("Failed to set read deadline", "address", rs.address, "err", err)
			dropConn()
			continue
		}

		req, err := ReadMsg(conn, rs.maxReadSize)
		if err != nil {
			rs.Logger.Error(
				"Failed to read message from connection",
				"address", rs.address,
				"err", err,
			)
			dropConn()
			continue
		}

		// handleRequestSafely answers requests it can resolve in time — including
		// signer refusals, which are sent back as RemoteSignerError. It signals
		// dropReq when the connection must instead be torn down without an answer:
		// a sign that exceeded signRequestTimeout (the node must see a retryable
		// transport error, not a terminal refusal), or a recovered panic on
		// malformed input (which must never crash the process).
		res, dropReq, panicked := rs.handleRequestSafely(ctx, req)
		if dropReq || panicked {
			dropConn()
			continue
		}

		if err := conn.SetWriteDeadline(time.Now().Add(rs.chainNodeWriteTimeout)); err != nil {
			rs.Logger.Error("Failed to set write deadline", "address", rs.address, "err", err)
			dropConn()
			continue
		}

		err = WriteMsg(conn, res)
		if err != nil {
			rs.Logger.Error(
				"Failed to write message to connection",
				"address", rs.address,
				"err", err,
			)
			dropConn()
		}
	}
}

// waitForLeadership blocks until this cosigner leads the signer cluster,
// returning false when the signer stops (or ctx ends) first. Signers without a
// leadership gate return immediately.
func (rs *ReconnRemoteSigner) waitForLeadership(ctx context.Context) bool {
	if rs.isLeader == nil || rs.isLeader() {
		return true
	}
	rs.Logger.Info("Not the cluster leader, deferring connection to chain node", "address", rs.address)
	ticker := time.NewTicker(leaderCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			if !rs.IsRunning() {
				return false
			}
			if rs.isLeader() {
				rs.Logger.Info("Elected cluster leader, connecting to chain node", "address", rs.address)
				return true
			}
		}
	}
}

// releaseConnOnLeadershipLoss closes conn when this cosigner loses cluster
// leadership, unblocking the request loop (which is typically parked in
// ReadMsg) so the chain node's single signer slot frees up for the new leader.
// stop ends the watch when the request loop tears the connection down itself.
func (rs *ReconnRemoteSigner) releaseConnOnLeadershipLoss(conn net.Conn, stop <-chan struct{}) {
	ticker := time.NewTicker(leaderCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if !rs.isLeader() {
				rs.Logger.Info("Lost cluster leadership, releasing connection to chain node", "address", rs.address)
				rs.closeConn(conn)
				return
			}
		}
	}
}

// handleRequestSafely wraps handleRequest so a panic on malformed input becomes a
// dropped connection rather than a process crash. It returns dropReq=true when
// the connection must be torn down without answering (see handleRequest), and
// panicked=true when a panic was recovered.
func (rs *ReconnRemoteSigner) handleRequestSafely(
	ctx context.Context,
	req cometprotoprivval.Message,
) (res cometprotoprivval.Message, dropReq bool, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			rs.Logger.Error(
				"Recovered from panic handling privval request",
				"address", rs.address,
				"panic", r,
			)
			panicked = true
		}
	}()
	res, dropReq = rs.handleRequest(ctx, req)
	return res, dropReq, false
}

// handleRequest resolves one privval request. The second return value is true
// when no response must be written and the connection must be dropped instead —
// the sign handlers use it for requests that ran out of time.
func (rs *ReconnRemoteSigner) handleRequest(
	ctx context.Context,
	req cometprotoprivval.Message,
) (cometprotoprivval.Message, bool) {
	switch typedReq := req.Sum.(type) {
	case *cometprotoprivval.Message_SignVoteRequest:
		return rs.handleSignVoteRequest(ctx, typedReq.SignVoteRequest.ChainId, typedReq.SignVoteRequest.Vote)
	case *cometprotoprivval.Message_SignProposalRequest:
		return rs.handleSignProposalRequest(ctx, typedReq.SignProposalRequest.ChainId, typedReq.SignProposalRequest.Proposal)
	case *cometprotoprivval.Message_PubKeyRequest:
		return rs.handlePubKeyRequest(ctx, typedReq.PubKeyRequest.ChainId), false
	case *cometprotoprivval.Message_PingRequest:
		return rs.handlePingRequest(), false
	default:
		rs.Logger.Error("Unknown request", "err", fmt.Errorf("%v", typedReq))
		return cometprotoprivval.Message{}, false
	}
}

// signWithTimeout runs signAndTrack, bounding how long the handler waits for an
// answer by rs.signRequestTimeout (derived from ctx, so shutdown aborts the wait
// too). The bound applies to the handler's answer only: parts of the sign path
// do not observe ctx (the raft election poll, the same-HRS condition wait), so
// an abandoned signing goroutine may keep running — its own internal timeouts
// (per-cosigner grpcTimeout, bounded polls) end it within single-digit seconds.
// The error returned on expiry wraps ctx.Err() so callers can classify it with
// errors.Is.
func (rs *ReconnRemoteSigner) signWithTimeout(
	ctx context.Context,
	chainID string,
	block Block,
) ([]byte, []byte, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, rs.signRequestTimeout)
	defer cancel()

	type signResult struct {
		sig        []byte
		voteExtSig []byte
		timestamp  time.Time
		err        error
	}
	// Buffered so the signing goroutine can always send and exit, even after a
	// timeout has abandoned the receiver.
	resultCh := make(chan signResult, 1)
	go func() {
		// A panic in the sign path must not kill the signer process; surfaced
		// as an error, it drops the chain node connection like any transient
		// sign failure. The channel is buffered, so this send only lands when
		// the normal send below never happened.
		defer func() {
			if r := recover(); r != nil {
				resultCh <- signResult{err: fmt.Errorf("panic in sign path: %v", r)}
			}
		}()
		sig, voteExtSig, timestamp, err := signAndTrack(ctx, rs.Logger, rs.privVal, chainID, block)
		resultCh <- signResult{sig, voteExtSig, timestamp, err}
	}()

	select {
	case r := <-resultCh:
		return r.sig, r.voteExtSig, r.timestamp, r.err
	case <-ctx.Done():
		return nil, nil, block.Timestamp,
			fmt.Errorf("sign request abandoned (timeout %s): %w", rs.signRequestTimeout, ctx.Err())
	}
}

// signRefusal reports whether a sign error is a deliberate slashing-protection
// refusal — a double-sign gate rejection the chain node must never retry. Only
// those are answered with a RemoteSignerError: tm2 wraps a response error into
// WrappedRemoteSignerError and treats it as terminal, never retried
// (retry_signer_client.shouldRetry). Every other sign error — timeout,
// shutdown, failed combine, missing cosigners, a recovered panic — drops the
// connection WITHOUT a response instead: that surfaces on the node as a
// transport error, which it retries (5 attempts, 1s apart, by default), and the
// re-dialed leader serves the retry from the cached signature if the abandoned
// attempt completed, or signs afresh.
//
// An abandoned attempt can leave some cosigners holding shares from a nonce set
// that a later retry does not use; that combine fails signature verification,
// drops the connection again, and so burns one of the node's retry attempts
// (nonce-cache follow-up), but no signature over conflicting payloads can
// result.
func signRefusal(err error) bool {
	var (
		beyondBlock   *BeyondBlockError
		heightReg     *HeightRegressionError
		roundReg      *RoundRegressionError
		stepReg       *StepRegressionError
		conflicting   *ConflictingDataError
		diffBlockIDs  *DiffBlockIDsError
		alreadySigned *AlreadySignedVoteError
		sameHRS       *SameHRSError
	)
	return errors.As(err, &beyondBlock) ||
		errors.As(err, &heightReg) ||
		errors.As(err, &roundReg) ||
		errors.As(err, &stepReg) ||
		errors.As(err, &conflicting) ||
		errors.As(err, &diffBlockIDs) ||
		errors.As(err, &alreadySigned) ||
		errors.As(err, &sameHRS)
}

func (rs *ReconnRemoteSigner) handleSignVoteRequest(
	ctx context.Context,
	chainID string,
	vote *cometproto.Vote,
) (cometprotoprivval.Message, bool) {
	msgSum := &cometprotoprivval.Message_SignedVoteResponse{SignedVoteResponse: &cometprotoprivval.SignedVoteResponse{
		Vote:  cometproto.Vote{},
		Error: nil,
	}}

	if err := ValidateChainID(chainID); err != nil {
		msgSum.SignedVoteResponse.Error = getRemoteSignerError(err)
		return cometprotoprivval.Message{Sum: msgSum}, false
	}
	if vote == nil {
		msgSum.SignedVoteResponse.Error = getRemoteSignerError(fmt.Errorf("vote is required"))
		return cometprotoprivval.Message{Sum: msgSum}, false
	}
	if vote.Type != cometproto.PrevoteType && vote.Type != cometproto.PrecommitType {
		msgSum.SignedVoteResponse.Error = getRemoteSignerError(fmt.Errorf("unexpected vote type: %v", vote.Type))
		return cometprotoprivval.Message{Sum: msgSum}, false
	}

	sig, voteExtSig, timestamp, err := rs.signWithTimeout(ctx, chainID, VoteToBlock(chainID, vote))
	if err != nil {
		if signRefusal(err) {
			msgSum.SignedVoteResponse.Error = getRemoteSignerError(err)
			return cometprotoprivval.Message{Sum: msgSum}, false
		}
		totalAbandonedSignRequests.WithLabelValues(chainID).Inc()
		rs.Logger.Error(
			"Sign vote request failed, dropping connection so the node retries",
			"chain_id", chainID,
			"height", vote.Height,
			"round", vote.Round,
			"err", err,
		)
		return cometprotoprivval.Message{}, true
	}

	// Echo the full request vote with only the signer-owned fields replaced: a
	// chain node validates the returned vote as a complete message (gno.land/tm2
	// rejects a vote whose validator address is empty), so dropping request
	// fields breaks strict nodes even though CometBFT only reads the signature.
	msgSum.SignedVoteResponse.Vote = *vote
	msgSum.SignedVoteResponse.Vote.Timestamp = timestamp
	msgSum.SignedVoteResponse.Vote.Signature = sig
	msgSum.SignedVoteResponse.Vote.ExtensionSignature = voteExtSig
	return cometprotoprivval.Message{Sum: msgSum}, false
}

func (rs *ReconnRemoteSigner) handleSignProposalRequest(
	ctx context.Context,
	chainID string,
	proposal *cometproto.Proposal,
) (cometprotoprivval.Message, bool) {
	msgSum := &cometprotoprivval.Message_SignedProposalResponse{
		SignedProposalResponse: &cometprotoprivval.SignedProposalResponse{
			Proposal: cometproto.Proposal{},
			Error:    nil,
		},
	}

	if err := ValidateChainID(chainID); err != nil {
		msgSum.SignedProposalResponse.Error = getRemoteSignerError(err)
		return cometprotoprivval.Message{Sum: msgSum}, false
	}
	if proposal == nil {
		msgSum.SignedProposalResponse.Error = getRemoteSignerError(fmt.Errorf("proposal is required"))
		return cometprotoprivval.Message{Sum: msgSum}, false
	}

	signature, _, timestamp, err := rs.signWithTimeout(ctx, chainID, ProposalToBlock(chainID, proposal))
	if err != nil {
		if signRefusal(err) {
			msgSum.SignedProposalResponse.Error = getRemoteSignerError(err)
			return cometprotoprivval.Message{Sum: msgSum}, false
		}
		totalAbandonedSignRequests.WithLabelValues(chainID).Inc()
		rs.Logger.Error(
			"Sign proposal request failed, dropping connection so the node retries",
			"chain_id", chainID,
			"height", proposal.Height,
			"round", proposal.Round,
			"err", err,
		)
		return cometprotoprivval.Message{}, true
	}

	// Same echo contract as the vote response: return the request proposal with
	// only the signature and timestamp filled in.
	msgSum.SignedProposalResponse.Proposal = *proposal
	msgSum.SignedProposalResponse.Proposal.Timestamp = timestamp
	msgSum.SignedProposalResponse.Proposal.Signature = signature
	return cometprotoprivval.Message{Sum: msgSum}, false
}

func (rs *ReconnRemoteSigner) handlePubKeyRequest(ctx context.Context, chainID string) cometprotoprivval.Message {
	msgSum := &cometprotoprivval.Message_PubKeyResponse{PubKeyResponse: &cometprotoprivval.PubKeyResponse{
		PubKey: cometprotocrypto.PublicKey{},
		Error:  nil,
	}}

	// Validate before touching a metric label: an unvalidated chain ID is both a
	// path-traversal input (single-signer mode) and an unbounded metric-label
	// cardinality DoS.
	if err := ValidateChainID(chainID); err != nil {
		msgSum.PubKeyResponse.Error = getRemoteSignerError(err)
		return cometprotoprivval.Message{Sum: msgSum}
	}

	totalPubKeyRequests.WithLabelValues(chainID).Inc()

	pubKey, err := rs.privVal.GetPubKey(ctx, chainID)
	if err != nil {
		rs.Logger.Error(
			"Failed to get Pub Key",
			"chain_id", chainID,
			"node", rs.address,
			"error", err,
		)
		msgSum.PubKeyResponse.Error = getRemoteSignerError(err)
		return cometprotoprivval.Message{Sum: msgSum}
	}
	pk, err := cometcryptoencoding.PubKeyToProto(cometcryptoed25519.PubKey(pubKey))
	if err != nil {
		rs.Logger.Error(
			"Failed to get Pub Key",
			"chain_id", chainID,
			"node", rs.address,
			"error", err,
		)
		msgSum.PubKeyResponse.Error = getRemoteSignerError(err)
		return cometprotoprivval.Message{Sum: msgSum}
	}
	msgSum.PubKeyResponse.PubKey = pk
	return cometprotoprivval.Message{Sum: msgSum}
}

func (rs *ReconnRemoteSigner) handlePingRequest() cometprotoprivval.Message {
	return cometprotoprivval.Message{
		Sum: &cometprotoprivval.Message_PingResponse{
			PingResponse: &cometprotoprivval.PingResponse{},
		},
	}
}

func getRemoteSignerError(err error) *cometprotoprivval.RemoteSignerError {
	if err == nil {
		return nil
	}
	return &cometprotoprivval.RemoteSignerError{
		Code:        0,
		Description: err.Error(),
	}
}

// StartRemoteSigners starts a signer for each chain node. connKey is the signer's
// persistent connection identity, shared by every node connection; a nil connKey
// presents a fresh identity per node connection. isLeader, when non-nil, gates
// every node connection on cluster leadership so only the current raft leader
// dials — required for chain nodes whose privval listener holds a single signer
// connection (tm2/gno.land). Nil preserves the always-dial behavior.
func StartRemoteSigners(
	services []cometservice.Service,
	logger cometlog.Logger,
	privVal PrivValidator,
	nodes []ChainNode,
	maxReadSize int,
	connKey cometcryptoed25519.PrivKey,
	isLeader func() bool,
) ([]cometservice.Service, error) {
	// Resolve every node's expected connection key up front so a malformed one
	// cannot leave a partially started set of signers behind.
	auths := make([]ConnAuth, len(nodes))
	for i, node := range nodes {
		nodePubKey, err := node.ConnPubKey()
		if err != nil {
			return nil, err
		}
		auths[i] = ConnAuth{PrivKey: connKey, NodePubKey: nodePubKey}
	}

	go StartMetrics()

	for i, node := range nodes {
		// CometBFT requires a connection within 3 seconds of start or crashes
		// A long timeout such as 30 seconds would cause the sentry to fail in loops
		// Use a short timeout and dial often to connect within 3 second window
		dialer := net.Dialer{Timeout: 2 * time.Second}
		s := NewReconnRemoteSigner(node.PrivValAddr, logger, privVal, dialer, maxReadSize, auths[i], isLeader)

		// A pin only protects a node the operator can confirm is pinned, and a
		// mistyped config key is otherwise indistinguishable from no pin at all.
		if auths[i].NodePubKey != nil {
			logger.Info(
				"Authenticating chain node",
				"address", node.PrivValAddr,
				"pub_key", node.ConnPubKeyHex,
			)
		}

		if err := s.Start(); err != nil {
			return nil, err
		}

		services = append(services, s)
	}

	return services, nil
}

func (rs *ReconnRemoteSigner) closeConn(conn net.Conn) {
	if conn == nil {
		return
	}
	// The leadership watcher and the request loop may both close the same
	// connection; the second close is a benign net.ErrClosed.
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		rs.Logger.Error("Failed to close connection to chain node",
			"address", rs.address,
			"err", err,
		)
	}
}

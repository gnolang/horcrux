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
	// defaultSignRequestTimeout bounds a single sign request end to end. It must
	// be shorter than the chain node's priv-validator read/write timeout
	// (CometBFT/tm2 default 5s) so the node always receives a response — success
	// or error — before it drops the connection, and longer than the per-cosigner
	// grpcTimeout so a normal sign round can complete.
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
	go rs.loop(context.Background())
	return nil
}

// OnStop implements cmn.Service.
func (rs *ReconnRemoteSigner) OnStop() {
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

		// handleRequest handles request errors. We always send back a response.
		// A malformed request must never panic the process (validator downtime);
		// recover and drop the connection, letting the node reconnect.
		res, panicked := rs.handleRequestSafely(req)
		if panicked {
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
// dropped connection rather than a process crash. It returns panicked=true when a
// panic was recovered.
func (rs *ReconnRemoteSigner) handleRequestSafely(
	req cometprotoprivval.Message,
) (res cometprotoprivval.Message, panicked bool) {
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
	return rs.handleRequest(req), false
}

func (rs *ReconnRemoteSigner) handleRequest(req cometprotoprivval.Message) cometprotoprivval.Message {
	switch typedReq := req.Sum.(type) {
	case *cometprotoprivval.Message_SignVoteRequest:
		return rs.handleSignVoteRequest(typedReq.SignVoteRequest.ChainId, typedReq.SignVoteRequest.Vote)
	case *cometprotoprivval.Message_SignProposalRequest:
		return rs.handleSignProposalRequest(typedReq.SignProposalRequest.ChainId, typedReq.SignProposalRequest.Proposal)
	case *cometprotoprivval.Message_PubKeyRequest:
		return rs.handlePubKeyRequest(typedReq.PubKeyRequest.ChainId)
	case *cometprotoprivval.Message_PingRequest:
		return rs.handlePingRequest()
	default:
		rs.Logger.Error("Unknown request", "err", fmt.Errorf("%v", typedReq))
		return cometprotoprivval.Message{}
	}
}

// signWithTimeout runs signAndTrack under signRequestTimeout so a stuck sign
// path can never hold the chain node's priv-validator connection past its
// read/write deadline. On expiry it returns a timeout error (the handlers turn
// that into a RemoteSignerError, so the node always gets an answer). The signing
// goroutine observes the same deadline via ctx and is otherwise bounded by
// horcrux's own per-cosigner grpcTimeout, so it does not leak indefinitely.
func (rs *ReconnRemoteSigner) signWithTimeout(chainID string, block Block) ([]byte, []byte, time.Time, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rs.signRequestTimeout)
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
		sig, voteExtSig, timestamp, err := signAndTrack(ctx, rs.Logger, rs.privVal, chainID, block)
		resultCh <- signResult{sig, voteExtSig, timestamp, err}
	}()

	select {
	case r := <-resultCh:
		return r.sig, r.voteExtSig, r.timestamp, r.err
	case <-ctx.Done():
		return nil, nil, block.Timestamp, fmt.Errorf("sign request timed out after %s", rs.signRequestTimeout)
	}
}

func (rs *ReconnRemoteSigner) handleSignVoteRequest(chainID string, vote *cometproto.Vote) cometprotoprivval.Message {
	msgSum := &cometprotoprivval.Message_SignedVoteResponse{SignedVoteResponse: &cometprotoprivval.SignedVoteResponse{
		Vote:  cometproto.Vote{},
		Error: nil,
	}}

	if err := ValidateChainID(chainID); err != nil {
		msgSum.SignedVoteResponse.Error = getRemoteSignerError(err)
		return cometprotoprivval.Message{Sum: msgSum}
	}
	if vote == nil {
		msgSum.SignedVoteResponse.Error = getRemoteSignerError(fmt.Errorf("vote is required"))
		return cometprotoprivval.Message{Sum: msgSum}
	}
	if vote.Type != cometproto.PrevoteType && vote.Type != cometproto.PrecommitType {
		msgSum.SignedVoteResponse.Error = getRemoteSignerError(fmt.Errorf("unexpected vote type: %v", vote.Type))
		return cometprotoprivval.Message{Sum: msgSum}
	}

	sig, voteExtSig, timestamp, err := rs.signWithTimeout(chainID, VoteToBlock(chainID, vote))
	if err != nil {
		msgSum.SignedVoteResponse.Error = getRemoteSignerError(err)
		return cometprotoprivval.Message{Sum: msgSum}
	}

	// Echo the full request vote with only the signer-owned fields replaced: a
	// chain node validates the returned vote as a complete message (gno.land/tm2
	// rejects a vote whose validator address is empty), so dropping request
	// fields breaks strict nodes even though CometBFT only reads the signature.
	msgSum.SignedVoteResponse.Vote = *vote
	msgSum.SignedVoteResponse.Vote.Timestamp = timestamp
	msgSum.SignedVoteResponse.Vote.Signature = sig
	msgSum.SignedVoteResponse.Vote.ExtensionSignature = voteExtSig
	return cometprotoprivval.Message{Sum: msgSum}
}

func (rs *ReconnRemoteSigner) handleSignProposalRequest(
	chainID string,
	proposal *cometproto.Proposal,
) cometprotoprivval.Message {
	msgSum := &cometprotoprivval.Message_SignedProposalResponse{
		SignedProposalResponse: &cometprotoprivval.SignedProposalResponse{
			Proposal: cometproto.Proposal{},
			Error:    nil,
		},
	}

	if err := ValidateChainID(chainID); err != nil {
		msgSum.SignedProposalResponse.Error = getRemoteSignerError(err)
		return cometprotoprivval.Message{Sum: msgSum}
	}
	if proposal == nil {
		msgSum.SignedProposalResponse.Error = getRemoteSignerError(fmt.Errorf("proposal is required"))
		return cometprotoprivval.Message{Sum: msgSum}
	}

	signature, _, timestamp, err := rs.signWithTimeout(chainID, ProposalToBlock(chainID, proposal))
	if err != nil {
		msgSum.SignedProposalResponse.Error = getRemoteSignerError(err)
		return cometprotoprivval.Message{Sum: msgSum}
	}

	// Same echo contract as the vote response: return the request proposal with
	// only the signature and timestamp filled in.
	msgSum.SignedProposalResponse.Proposal = *proposal
	msgSum.SignedProposalResponse.Proposal.Timestamp = timestamp
	msgSum.SignedProposalResponse.Proposal.Signature = signature
	return cometprotoprivval.Message{Sum: msgSum}
}

func (rs *ReconnRemoteSigner) handlePubKeyRequest(chainID string) cometprotoprivval.Message {
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

	pubKey, err := rs.privVal.GetPubKey(context.TODO(), chainID)
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

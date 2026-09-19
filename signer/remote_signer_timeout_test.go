package signer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometlog "github.com/cometbft/cometbft/libs/log"
	cometp2pconn "github.com/cometbft/cometbft/p2p/conn"
	cometprotoprivval "github.com/cometbft/cometbft/proto/tendermint/privval"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// blockingPrivVal is a PrivValidator whose Sign blocks until its context is
// cancelled, modeling a stuck sign path (a dead or flapping peer, or a hung
// nonce wait).
type blockingPrivVal struct{}

func (blockingPrivVal) Sign(ctx context.Context, _ string, block Block) ([]byte, []byte, time.Time, error) {
	<-ctx.Done()
	return nil, nil, block.Timestamp, ctx.Err()
}
func (blockingPrivVal) GetPubKey(context.Context, string) ([]byte, error) { return nil, nil }
func (blockingPrivVal) Stop()                                             {}

// refusingPrivVal is a PrivValidator whose Sign fails with a slashing-protection
// refusal, modeling a double-sign gate rejection the node must never retry.
type refusingPrivVal struct{}

func (refusingPrivVal) Sign(_ context.Context, _ string, block Block) ([]byte, []byte, time.Time, error) {
	return nil, nil, block.Timestamp, &BeyondBlockError{msg: "sign refused by test validator"}
}
func (refusingPrivVal) GetPubKey(context.Context, string) ([]byte, error) { return nil, nil }
func (refusingPrivVal) Stop()                                             {}

// failingPrivVal is a PrivValidator whose Sign fails with a transient cluster
// error (a failed combine, missing cosigners), which the node should retry.
type failingPrivVal struct{}

func (failingPrivVal) Sign(_ context.Context, _ string, block Block) ([]byte, []byte, time.Time, error) {
	return nil, nil, block.Timestamp, errors.New("combined signature is not valid")
}
func (failingPrivVal) GetPubKey(context.Context, string) ([]byte, error) { return nil, nil }
func (failingPrivVal) Stop()                                             {}

// panickingPrivVal is a PrivValidator whose Sign panics, modeling an unexpected
// defect in the sign path (an unknown sign step, a corrupted sign state).
type panickingPrivVal struct{}

func (panickingPrivVal) Sign(_ context.Context, _ string, _ Block) ([]byte, []byte, time.Time, error) {
	panic("test panic in sign path")
}
func (panickingPrivVal) GetPubKey(context.Context, string) ([]byte, error) { return nil, nil }
func (panickingPrivVal) Stop()                                             {}

// signHandlerCases drives both sign handlers through the same scenario: the
// vote and proposal paths must classify outcomes identically.
var signHandlerCases = []struct {
	name string
	call func(rs *ReconnRemoteSigner, ctx context.Context) (cometprotoprivval.Message, bool)
	err  func(res cometprotoprivval.Message) *cometprotoprivval.RemoteSignerError
}{
	{
		name: "vote",
		call: func(rs *ReconnRemoteSigner, ctx context.Context) (cometprotoprivval.Message, bool) {
			vote := cometproto.Vote{Type: cometproto.PrecommitType, Height: 1, Round: 0}
			return rs.handleSignVoteRequest(ctx, "test-chain", &vote)
		},
		err: func(res cometprotoprivval.Message) *cometprotoprivval.RemoteSignerError {
			return res.GetSignedVoteResponse().GetError()
		},
	},
	{
		name: "proposal",
		call: func(rs *ReconnRemoteSigner, ctx context.Context) (cometprotoprivval.Message, bool) {
			proposal := cometproto.Proposal{Type: cometproto.ProposalType, Height: 1, Round: 0}
			return rs.handleSignProposalRequest(ctx, "test-chain", &proposal)
		},
		err: func(res cometprotoprivval.Message) *cometprotoprivval.RemoteSignerError {
			return res.GetSignedProposalResponse().GetError()
		},
	},
}

// A sign request that exceeds signRequestTimeout must signal the request loop
// to drop the connection without answering: tm2 treats a RemoteSignerError
// response as a terminal signer refusal (never retried), while a dropped
// connection is a transport error that the node's retry budget handles.
func TestSignHandlerTimeoutDropsConnection(t *testing.T) {
	for _, tc := range signHandlerCases {
		t.Run(tc.name, func(t *testing.T) {
			rs := NewReconnRemoteSigner(
				"tcp://127.0.0.1:0", cometlog.NewNopLogger(), blockingPrivVal{},
				net.Dialer{}, 1024*1024, ConnAuth{}, nil,
			)
			rs.signRequestTimeout = 100 * time.Millisecond

			type result struct {
				res  cometprotoprivval.Message
				drop bool
			}
			done := make(chan result, 1)
			go func() {
				res, drop := tc.call(rs, context.Background())
				done <- result{res, drop}
			}()

			select {
			case r := <-done:
				require.True(t, r.drop,
					"a timed-out sign must drop the connection so the node retries; "+
						"an answer would be a terminal refusal on tm2")
			case <-time.After(2 * time.Second):
				t.Fatal("handler did not return within the sign timeout — it blocked on Sign")
			}
		})
	}
}

// A transient sign failure (failed combine, missing cosigners, exceeded
// attempts) must drop the connection like a timeout does: answering makes the
// node treat a recoverable cluster hiccup as a terminal refusal.
func TestSignHandlerTransientErrorDropsConnection(t *testing.T) {
	for _, tc := range signHandlerCases {
		t.Run(tc.name, func(t *testing.T) {
			rs := NewReconnRemoteSigner(
				"tcp://127.0.0.1:0", cometlog.NewNopLogger(), failingPrivVal{},
				net.Dialer{}, 1024*1024, ConnAuth{}, nil,
			)

			_, drop := tc.call(rs, context.Background())
			require.True(t, drop,
				"a transient sign failure must drop the connection so the node retries")
		})
	}
}

// A panic in the sign path must be contained: the handler drops the connection
// and the signer process survives to serve the node's retry.
func TestSignHandlerPanicDropsConnection(t *testing.T) {
	for _, tc := range signHandlerCases {
		t.Run(tc.name, func(t *testing.T) {
			rs := NewReconnRemoteSigner(
				"tcp://127.0.0.1:0", cometlog.NewNopLogger(), panickingPrivVal{},
				net.Dialer{}, 1024*1024, ConnAuth{}, nil,
			)

			_, drop := tc.call(rs, context.Background())
			require.True(t, drop, "a sign panic must drop the connection, not kill the signer")
		})
	}
}

// A slashing-protection refusal (a double-sign gate rejection) must still be
// answered with a RemoteSignerError and must not drop the connection: the node
// is correct to treat it as terminal and must never retry it.
func TestSignHandlerRefusalAnswersWithError(t *testing.T) {
	for _, tc := range signHandlerCases {
		t.Run(tc.name, func(t *testing.T) {
			rs := NewReconnRemoteSigner(
				"tcp://127.0.0.1:0", cometlog.NewNopLogger(), refusingPrivVal{},
				net.Dialer{}, 1024*1024, ConnAuth{}, nil,
			)

			res, drop := tc.call(rs, context.Background())
			require.False(t, drop, "a signer refusal must be answered, not dropped")
			rse := tc.err(res)
			require.NotNil(t, rse, "a signer refusal must carry a RemoteSignerError")
			require.Contains(t, rse.Description, "sign refused by test validator")
		})
	}
}

// Cancelling the signer's context (shutdown) must abort an in-flight sign and
// signal a drop rather than answer.
func TestSignHandlerShutdownAbortsSign(t *testing.T) {
	rs := NewReconnRemoteSigner(
		"tcp://127.0.0.1:0", cometlog.NewNopLogger(), blockingPrivVal{},
		net.Dialer{}, 1024*1024, ConnAuth{}, nil,
	)

	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		drop bool
	}
	done := make(chan result, 1)
	go func() {
		vote := cometproto.Vote{Type: cometproto.PrecommitType, Height: 1, Round: 0}
		_, drop := rs.handleSignVoteRequest(ctx, "test-chain", &vote)
		done <- result{drop}
	}()

	cancel()
	select {
	case r := <-done:
		require.True(t, r.drop, "a cancelled sign must signal a drop, not an answer")
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not observe context cancellation")
	}
}

// A chain node that connects and then goes silent (dead or half-open socket)
// must trip the connection read deadline so the signer drops and re-dials while
// still leader, rather than blocking forever in ReadMsg.
func TestChainNodeReadDeadlineRedials(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	accepted := make(chan struct{}, 8)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			// Complete the signer's SecretConnection handshake, then stay silent
			// (never send a request), modeling a dead/half-open chain node.
			go func(c net.Conn) {
				_, _ = cometp2pconn.MakeSecretConnection(c, cometcryptoed25519.GenPrivKey())
			}(raw)
		}
	}()

	rs := NewReconnRemoteSigner(
		"tcp://"+ln.Addr().String(), cometlog.NewNopLogger(), nopPrivVal{},
		net.Dialer{Timeout: 2 * time.Second}, 1024*1024, ConnAuth{}, nil,
	)
	rs.chainNodeReadTimeout = 200 * time.Millisecond
	require.NoError(t, rs.Start())
	defer func() { _ = rs.Stop() }()

	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("signer did not dial the chain node")
	}
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("signer did not re-dial after the read deadline expired on a silent node")
	}
}

// A refusal raised by a peer cosigner crosses the cluster RPC as a plain
// string: gRPC erases the error type and the leader aggregates cosigner errors
// with %s. The classifier must still recognize those as refusals — answering
// them terminally — rather than dropping the chain node connection and sending
// the node into a futile retry loop. Transient failures must stay unclassified
// so the connection drop keeps triggering the node's retries.
func TestSignRefusalClassifiesRefusalsAcrossClusterRPC(t *testing.T) {
	// The inputs derive from the refusal constructors so a change to any
	// Error() text breaks this test at the point of the change: string matching
	// across the RPC boundary is only as strong as this coupling.
	rpcWrap := func(err error) error {
		return fmt.Errorf("error from cosigner(s): rpc error: code = Unknown desc = %s", err.Error())
	}
	refusals := []error{
		rpcWrap(newHeightRegressionError(163330, 163335)),
		rpcWrap(newRoundRegressionError(12, 0, 1)),
		rpcWrap(newStepRegressionError(12, 0, 2, 3)),
		rpcWrap(newConflictingDataError([]byte("abc"), []byte("def"))),
		rpcWrap(newDiffBlockIDsError([]byte{0xaa}, []byte{0xbb})),
		rpcWrap(newAlreadySignedVoteError(true)),
		rpcWrap(newSameHRSError(HRSKey{Height: 12, Round: 0, Step: 3})),
		fmt.Errorf("rpc error: code = Unknown desc = %s",
			(&BeyondBlockError{msg: "[gnoland-1] Progress already started on block 12.0.3, skipping 12.0.2"}).Error()),
		// Single-signer mode raises these without a type (signer/file.go).
		errors.New("conflicting data"),
		ErrEmptySignBytes,
	}
	for _, err := range refusals {
		require.True(t, signRefusal(err), "must classify as refusal: %s", err)
	}

	transients := []string{
		"error from cosigner(s): rpc error: code = Unavailable desc = connection refused",
		"error from cosigner(s): context deadline exceeded",
		"sign request abandoned (timeout 3.5s): context deadline exceeded",
		"combined signature is not valid",
		"not enough cosigners",
		"exceeded max attempts waiting for block to be signed",
	}
	for _, msg := range transients {
		require.False(t, signRefusal(errors.New(msg)), "must stay transient: %s", msg)
	}
}

// The peer keepalive ping interval must stay at or above the cosigner gRPC
// server's enforcement MinTime; otherwise the server GOAWAYs peer connections
// with "too_many_pings" and the cluster transport breaks. This guards both
// values from drifting into that misconfiguration.
func TestPeerKeepaliveRespectsServerEnforcement(t *testing.T) {
	params := peerKeepalive()
	require.GreaterOrEqual(t, params.Time, peerKeepaliveMinTime,
		"peerKeepalive Time must be >= the server's KeepaliveEnforcementPolicy MinTime")
	require.True(t, params.PermitWithoutStream,
		"peer keepalive must ping without an active stream so idle-but-dead peers are detected")
}

// Each handler outcome must tick its per-node counter with the right labels:
// the metric is the operator's replacement for grepping refusal logs.
func TestChainNodeSignResultsMetricLabels(t *testing.T) {
	const address = "tcp://metrics-test:1234"
	count := func(result string) float64 {
		return testutil.ToFloat64(chainNodeSignResults.WithLabelValues("test-chain", address, result))
	}

	for _, tc := range []struct {
		result  string
		privVal PrivValidator
	}{
		{result: "signed", privVal: echoPrivVal{}},
		{result: "refused", privVal: refusingPrivVal{}},
		{result: "dropped", privVal: failingPrivVal{}},
	} {
		before := count(tc.result)
		rs := NewReconnRemoteSigner(
			address, cometlog.NewNopLogger(), tc.privVal,
			net.Dialer{}, 1024*1024, ConnAuth{}, nil,
		)
		vote := cometproto.Vote{Type: cometproto.PrecommitType, Height: 1, Round: 0}
		rs.handleSignVoteRequest(context.Background(), "test-chain", &vote)
		require.Equal(t, before+1, count(tc.result), "outcome %q must increment its counter", tc.result)
	}
}

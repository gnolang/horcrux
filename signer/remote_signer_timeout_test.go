package signer

import (
	"context"
	"net"
	"testing"
	"time"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometlog "github.com/cometbft/cometbft/libs/log"
	cometp2pconn "github.com/cometbft/cometbft/p2p/conn"
	cometprotoprivval "github.com/cometbft/cometbft/proto/tendermint/privval"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
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

// A sign request must never hold the chain node's priv-validator connection past
// the node's read/write deadline: the handler bounds signing at
// signRequestTimeout and returns a RemoteSignerError rather than blocking.
func TestHandleSignVoteRequestTimesOut(t *testing.T) {
	rs := NewReconnRemoteSigner(
		"tcp://127.0.0.1:0", cometlog.NewNopLogger(), blockingPrivVal{},
		net.Dialer{}, 1024*1024, ConnAuth{}, nil,
	)
	rs.signRequestTimeout = 100 * time.Millisecond

	vote := cometproto.Vote{Type: cometproto.PrecommitType, Height: 1, Round: 0}

	done := make(chan cometprotoprivval.Message, 1)
	go func() { done <- rs.handleSignVoteRequest("test-chain", &vote) }()

	select {
	case res := <-done:
		signed := res.GetSignedVoteResponse()
		require.NotNil(t, signed)
		require.NotNil(t, signed.Error, "a timed-out sign must return a RemoteSignerError")
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return within the sign timeout — it blocked on Sign")
	}
}

func TestHandleSignProposalRequestTimesOut(t *testing.T) {
	rs := NewReconnRemoteSigner(
		"tcp://127.0.0.1:0", cometlog.NewNopLogger(), blockingPrivVal{},
		net.Dialer{}, 1024*1024, ConnAuth{}, nil,
	)
	rs.signRequestTimeout = 100 * time.Millisecond

	proposal := cometproto.Proposal{Type: cometproto.ProposalType, Height: 1, Round: 0}

	done := make(chan cometprotoprivval.Message, 1)
	go func() { done <- rs.handleSignProposalRequest("test-chain", &proposal) }()

	select {
	case res := <-done:
		signed := res.GetSignedProposalResponse()
		require.NotNil(t, signed)
		require.NotNil(t, signed.Error, "a timed-out sign must return a RemoteSignerError")
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return within the sign timeout — it blocked on Sign")
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

// The peer keepalive ping interval must stay at or above the cosigner gRPC
// server's enforcement MinTime; otherwise the server GOAWAYs peer connections
// with "too_many_pings" and the cluster transport breaks. This guards both
// values from drifting into that misconfiguration.
func TestPeerKeepaliveRespectsServerEnforcement(t *testing.T) {
	require.GreaterOrEqual(t, peerKeepalive.Time, peerKeepaliveMinTime,
		"peerKeepalive.Time must be >= the server's KeepaliveEnforcementPolicy MinTime")
	require.True(t, peerKeepalive.PermitWithoutStream,
		"peer keepalive must ping without an active stream so idle-but-dead peers are detected")
}

package signer

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometlog "github.com/cometbft/cometbft/libs/log"
	cometp2pconn "github.com/cometbft/cometbft/p2p/conn"
	"github.com/stretchr/testify/require"
)

// nopPrivVal is a no-op PrivValidator so the signer under test can be
// stopped safely; the gating tests never exercise the sign path.
type nopPrivVal struct{}

func (nopPrivVal) Sign(context.Context, string, Block) ([]byte, []byte, time.Time, error) {
	return nil, nil, time.Time{}, nil
}
func (nopPrivVal) GetPubKey(context.Context, string) ([]byte, error) { return nil, nil }
func (nopPrivVal) Stop()                                             {}

// TestLeaderGatedSignerConnection asserts the leader-only connection mode: a
// follower never dials the chain node, a cosigner that gains leadership dials,
// and a leader that loses leadership releases its connection so the node's
// single slot frees up for the new leader.
func TestLeaderGatedSignerConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	var leader atomic.Bool
	rs := NewReconnRemoteSigner(
		"tcp://"+ln.Addr().String(),
		cometlog.NewNopLogger(),
		nopPrivVal{},
		net.Dialer{Timeout: 2 * time.Second},
		1024,
		ConnAuth{},
		leader.Load,
	)
	require.NoError(t, rs.Start())
	defer func() { _ = rs.Stop() }()

	// A follower must not dial the chain node.
	select {
	case <-accepted:
		t.Fatal("follower dialed the chain node")
	case <-time.After(1 * time.Second):
	}

	// On gaining leadership the signer must dial.
	leader.Store(true)
	var raw net.Conn
	select {
	case raw = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("leader did not dial the chain node")
	}

	// Complete the node side of the SecretConnection handshake so the signer
	// holds an established connection and blocks reading requests.
	nodeKey := cometcryptoed25519.GenPrivKey()
	nodeConn, err := cometp2pconn.MakeSecretConnection(raw, nodeKey)
	require.NoError(t, err)

	// On losing leadership the signer must close the connection: the node-side
	// read must fail with a peer close, not run into its own read deadline.
	leader.Store(false)
	require.NoError(t, nodeConn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = nodeConn.Read(make([]byte, 1))
	require.Error(t, err, "connection must be closed after leadership loss")
	var netErr net.Error
	if errors.As(err, &netErr) {
		require.False(t, netErr.Timeout(),
			"connection was not released on leadership loss (read hit its deadline instead)")
	}

	// On regaining leadership the signer must dial again.
	leader.Store(true)
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("re-elected leader did not reconnect")
	}
}

// TestUngatedSignerAlwaysDials asserts that a signer without a leadership
// gate (single-signer mode, or leader-only mode disabled) dials immediately.
func TestUngatedSignerAlwaysDials(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	rs := NewReconnRemoteSigner(
		"tcp://"+ln.Addr().String(),
		cometlog.NewNopLogger(),
		nopPrivVal{},
		net.Dialer{Timeout: 2 * time.Second},
		1024,
		ConnAuth{},
		nil,
	)
	require.NoError(t, rs.Start())
	defer func() { _ = rs.Stop() }()

	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("ungated signer did not dial the chain node")
	}
}

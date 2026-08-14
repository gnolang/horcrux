package signer

import (
	"context"
	"net"
	"testing"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometlog "github.com/cometbft/cometbft/libs/log"
	cometp2pconn "github.com/cometbft/cometbft/p2p/conn"
	"github.com/stretchr/testify/require"
)

// nodePrivvalListener stands in for a chain node's privval listener. It accepts
// connections, completes the SecretConnection handshake using nodeKey, and
// publishes the connection public key that each signer presented.
func nodePrivvalListener(t *testing.T, nodeKey cometcryptoed25519.PrivKey) (string, <-chan cometcrypto.PubKey) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	observed := make(chan cometcrypto.PubKey, 8)
	done := make(chan struct{})

	t.Cleanup(func() {
		close(done)
		_ = listener.Close()
	})

	// Accepts until the listener is closed by the test cleanup.
	go func() {
		for {
			netConn, err := listener.Accept()
			if err != nil {
				return
			}

			// Handshakes, then holds the connection open until cleanup so the
			// signer side always observes a complete handshake.
			go func() {
				sc, err := cometp2pconn.MakeSecretConnection(netConn, nodeKey)
				if err != nil {
					_ = netConn.Close()
					return
				}
				observed <- sc.RemotePubKey()
				<-done
				_ = sc.Close()
			}()
		}
	}()

	return "tcp://" + listener.Addr().String(), observed
}

func TestEstablishConnectionNodeAuth(t *testing.T) {
	nodeKey := cometcryptoed25519.GenPrivKey()

	t.Run("unauthenticated node connects", func(t *testing.T) {
		address, _ := nodePrivvalListener(t, nodeKey)
		rs := NewReconnRemoteSigner(address, cometlog.NewNopLogger(), nil, net.Dialer{}, 1024, ConnAuth{})

		conn, err := rs.establishConnection(context.Background())
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	})

	t.Run("matching node public key connects", func(t *testing.T) {
		address, _ := nodePrivvalListener(t, nodeKey)
		rs := NewReconnRemoteSigner(address, cometlog.NewNopLogger(), nil, net.Dialer{}, 1024, ConnAuth{
			NodePubKey: nodeKey.PubKey().(cometcryptoed25519.PubKey),
		})

		conn, err := rs.establishConnection(context.Background())
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	})

	t.Run("mismatched node public key is refused", func(t *testing.T) {
		address, _ := nodePrivvalListener(t, nodeKey)
		impostor := cometcryptoed25519.GenPrivKey().PubKey().(cometcryptoed25519.PubKey)
		rs := NewReconnRemoteSigner(address, cometlog.NewNopLogger(), nil, net.Dialer{}, 1024, ConnAuth{
			NodePubKey: impostor,
		})

		conn, err := rs.establishConnection(context.Background())
		require.ErrorIs(t, err, ErrConnPubKeyMismatch)
		require.Nil(t, conn)
	})

	t.Run("persistent connection key is presented to the node", func(t *testing.T) {
		address, observed := nodePrivvalListener(t, nodeKey)
		connKey := cometcryptoed25519.GenPrivKey()
		rs := NewReconnRemoteSigner(address, cometlog.NewNopLogger(), nil, net.Dialer{}, 1024, ConnAuth{
			PrivKey: connKey,
		})

		conn, err := rs.establishConnection(context.Background())
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		require.True(t, connKey.PubKey().Equals(<-observed))
	})
}

func TestStartRemoteSigners(t *testing.T) {
	t.Run("a malformed node public key starts no signers", func(t *testing.T) {
		nodes := []ChainNode{
			{PrivValAddr: "tcp://127.0.0.1:1"},
			{PrivValAddr: "tcp://127.0.0.1:2", ConnPubKeyHex: "beefbeef"},
		}

		services, err := StartRemoteSigners(nil, cometlog.NewNopLogger(), nil, nodes, 1024, nil)
		require.Error(t, err)
		require.Empty(t, services)
	})
}

func TestConnAuthPrivKey(t *testing.T) {
	t.Run("no key generates a distinct identity per signer", func(t *testing.T) {
		a := NewReconnRemoteSigner("tcp://127.0.0.1:1", cometlog.NewNopLogger(), nil, net.Dialer{}, 1024, ConnAuth{})
		b := NewReconnRemoteSigner("tcp://127.0.0.1:2", cometlog.NewNopLogger(), nil, net.Dialer{}, 1024, ConnAuth{})

		require.NotEqual(t, a.privKey, b.privKey)
	})

	t.Run("a persistent key is shared by every signer", func(t *testing.T) {
		connKey := cometcryptoed25519.GenPrivKey()
		auth := ConnAuth{PrivKey: connKey}
		a := NewReconnRemoteSigner("tcp://127.0.0.1:1", cometlog.NewNopLogger(), nil, net.Dialer{}, 1024, auth)
		b := NewReconnRemoteSigner("tcp://127.0.0.1:2", cometlog.NewNopLogger(), nil, net.Dialer{}, 1024, auth)

		require.Equal(t, connKey, a.privKey)
		require.Equal(t, a.privKey, b.privKey)
	})
}

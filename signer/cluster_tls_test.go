package signer

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/stretchr/testify/require"
)

// tlsHandshake dials a server and reports whether the mutual-TLS handshake
// (with pubkey pinning on both ends) succeeds.
func tlsHandshake(t *testing.T, serverCfg, clientCfg *tls.Config) error {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	require.NoError(t, err)
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		// Force the handshake to complete (Accept is lazy).
		serverErr <- conn.(*tls.Conn).HandshakeContext(context.Background())
	}()

	dialer := &tls.Dialer{Config: clientCfg}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		return err
	}
	_ = conn.Close()

	select {
	case err := <-serverErr:
		return err
	case <-time.After(3 * time.Second):
		return context.DeadlineExceeded
	}
}

func TestClusterTLSConfig(t *testing.T) {
	a := cometcryptoed25519.GenPrivKey()
	b := cometcryptoed25519.GenPrivKey()
	c := cometcryptoed25519.GenPrivKey()

	pub := func(k cometcryptoed25519.PrivKey) cometcryptoed25519.PubKey {
		return k.PubKey().(cometcryptoed25519.PubKey)
	}

	t.Run("peers on each other's allowlist connect", func(t *testing.T) {
		serverCfg, err := clusterTLSConfig(a, []cometcryptoed25519.PubKey{pub(a), pub(b)})
		require.NoError(t, err)
		clientCfg, err := clusterTLSConfig(b, []cometcryptoed25519.PubKey{pub(a), pub(b)})
		require.NoError(t, err)

		require.NoError(t, tlsHandshake(t, serverCfg, clientCfg))
	})

	t.Run("client not on server allowlist is rejected", func(t *testing.T) {
		// Server allows only a and b; client c presents an unlisted identity.
		serverCfg, err := clusterTLSConfig(a, []cometcryptoed25519.PubKey{pub(a), pub(b)})
		require.NoError(t, err)
		clientCfg, err := clusterTLSConfig(c, []cometcryptoed25519.PubKey{pub(a), pub(b), pub(c)})
		require.NoError(t, err)

		require.Error(t, tlsHandshake(t, serverCfg, clientCfg))
	})

	t.Run("server not on client allowlist is rejected", func(t *testing.T) {
		// Client trusts only b and c; the server presents a, which the client
		// does not allow.
		serverCfg, err := clusterTLSConfig(a, []cometcryptoed25519.PubKey{pub(a), pub(b), pub(c)})
		require.NoError(t, err)
		clientCfg, err := clusterTLSConfig(b, []cometcryptoed25519.PubKey{pub(b), pub(c)})
		require.NoError(t, err)

		require.Error(t, tlsHandshake(t, serverCfg, clientCfg))
	})
}

var _ = net.Listen

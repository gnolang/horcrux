package signer

import (
	"context"
	"net"
	"testing"
	"time"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometlog "github.com/cometbft/cometbft/libs/log"
	cometp2pconn "github.com/cometbft/cometbft/p2p/conn"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
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
		rs := NewReconnRemoteSigner(address, cometlog.NewNopLogger(), nil, net.Dialer{}, 1024, ConnAuth{}, nil)

		conn, err := rs.establishConnection(context.Background())
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	})

	t.Run("matching node public key connects", func(t *testing.T) {
		address, _ := nodePrivvalListener(t, nodeKey)
		rs := NewReconnRemoteSigner(address, cometlog.NewNopLogger(), nil, net.Dialer{}, 1024, ConnAuth{
			NodePubKey: nodeKey.PubKey().(cometcryptoed25519.PubKey),
		}, nil)

		conn, err := rs.establishConnection(context.Background())
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	})

	t.Run("mismatched node public key is refused", func(t *testing.T) {
		address, _ := nodePrivvalListener(t, nodeKey)
		impostor := cometcryptoed25519.GenPrivKey().PubKey().(cometcryptoed25519.PubKey)
		rs := NewReconnRemoteSigner(address, cometlog.NewNopLogger(), nil, net.Dialer{}, 1024, ConnAuth{
			NodePubKey: impostor,
		}, nil)

		conn, err := rs.establishConnection(context.Background())
		require.ErrorIs(t, err, ErrConnPubKeyMismatch)
		require.Nil(t, conn)
	})

	t.Run("persistent connection key is presented to the node", func(t *testing.T) {
		address, observed := nodePrivvalListener(t, nodeKey)
		connKey := cometcryptoed25519.GenPrivKey()
		rs := NewReconnRemoteSigner(address, cometlog.NewNopLogger(), nil, net.Dialer{}, 1024, ConnAuth{
			PrivKey: connKey,
		}, nil)

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

		services, err := StartRemoteSigners(nil, cometlog.NewNopLogger(), nil, nodes, 1024, nil, nil)
		require.Error(t, err)
		require.Empty(t, services)
	})
}

func TestConnAuthPrivKey(t *testing.T) {
	t.Run("no key generates a distinct identity per signer", func(t *testing.T) {
		a := NewReconnRemoteSigner("tcp://127.0.0.1:1", cometlog.NewNopLogger(), nil, net.Dialer{}, 1024, ConnAuth{}, nil)
		b := NewReconnRemoteSigner("tcp://127.0.0.1:2", cometlog.NewNopLogger(), nil, net.Dialer{}, 1024, ConnAuth{}, nil)

		require.NotEqual(t, a.privKey, b.privKey)
	})

	t.Run("a persistent key is shared by every signer", func(t *testing.T) {
		connKey := cometcryptoed25519.GenPrivKey()
		auth := ConnAuth{PrivKey: connKey}
		a := NewReconnRemoteSigner("tcp://127.0.0.1:1", cometlog.NewNopLogger(), nil, net.Dialer{}, 1024, auth, nil)
		b := NewReconnRemoteSigner("tcp://127.0.0.1:2", cometlog.NewNopLogger(), nil, net.Dialer{}, 1024, auth, nil)

		require.Equal(t, connKey, a.privKey)
		require.Equal(t, a.privKey, b.privKey)
	})
}

// echoPrivVal is a PrivValidator stub returning a fixed signature so handler
// tests can assert response construction without a cosigner cluster.
type echoPrivVal struct{}

func (echoPrivVal) Sign(_ context.Context, _ string, block Block) ([]byte, []byte, time.Time, error) {
	return []byte("test-signature"), nil, block.Timestamp, nil
}
func (echoPrivVal) GetPubKey(context.Context, string) ([]byte, error) { return nil, nil }
func (echoPrivVal) Stop()                                             {}

// A chain node verifies the signed vote/proposal it gets back as a complete
// message (gno.land/tm2 rejects a vote whose validator address is empty), so
// the response must echo every request field, with only the signature and
// timestamp filled in by the signer.
func TestHandleSignVoteRequestEchoesVote(t *testing.T) {
	rs := NewReconnRemoteSigner(
		"tcp://127.0.0.1:0", cometlog.NewNopLogger(), echoPrivVal{},
		net.Dialer{}, 1024*1024, ConnAuth{}, nil,
	)

	vote := cometproto.Vote{
		Type:   cometproto.PrecommitType,
		Height: 42,
		Round:  1,
		BlockID: cometproto.BlockID{
			Hash:          []byte("0123456789abcdef0123456789abcdef"),
			PartSetHeader: cometproto.PartSetHeader{Total: 3, Hash: []byte("fedcba9876543210fedcba9876543210")},
		},
		Timestamp:        time.Unix(1700000000, 0).UTC(),
		ValidatorAddress: []byte("01234567890123456789"),
		ValidatorIndex:   7,
	}

	res := rs.handleSignVoteRequest("test-chain", &vote)
	signed := res.GetSignedVoteResponse()
	require.NotNil(t, signed)
	require.Nil(t, signed.Error)

	require.Equal(t, vote.ValidatorAddress, signed.Vote.ValidatorAddress)
	require.Equal(t, vote.ValidatorIndex, signed.Vote.ValidatorIndex)
	require.Equal(t, vote.Type, signed.Vote.Type)
	require.Equal(t, vote.Height, signed.Vote.Height)
	require.Equal(t, vote.Round, signed.Vote.Round)
	require.Equal(t, vote.BlockID, signed.Vote.BlockID)
	require.Equal(t, []byte("test-signature"), signed.Vote.Signature)
}

func TestHandleSignProposalRequestEchoesProposal(t *testing.T) {
	rs := NewReconnRemoteSigner(
		"tcp://127.0.0.1:0", cometlog.NewNopLogger(), echoPrivVal{},
		net.Dialer{}, 1024*1024, ConnAuth{}, nil,
	)

	proposal := cometproto.Proposal{
		Type:     cometproto.ProposalType,
		Height:   42,
		Round:    1,
		PolRound: -1,
		BlockID: cometproto.BlockID{
			Hash:          []byte("0123456789abcdef0123456789abcdef"),
			PartSetHeader: cometproto.PartSetHeader{Total: 3, Hash: []byte("fedcba9876543210fedcba9876543210")},
		},
		Timestamp: time.Unix(1700000000, 0).UTC(),
	}

	res := rs.handleSignProposalRequest("test-chain", &proposal)
	signed := res.GetSignedProposalResponse()
	require.NotNil(t, signed)
	require.Nil(t, signed.Error)

	require.Equal(t, proposal.Type, signed.Proposal.Type)
	require.Equal(t, proposal.Height, signed.Proposal.Height)
	require.Equal(t, proposal.Round, signed.Proposal.Round)
	require.Equal(t, proposal.PolRound, signed.Proposal.PolRound)
	require.Equal(t, proposal.BlockID, signed.Proposal.BlockID)
	require.Equal(t, []byte("test-signature"), signed.Proposal.Signature)
}

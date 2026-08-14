package signer

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometcryptosecp256k1 "github.com/cometbft/cometbft/crypto/secp256k1"
	cometp2p "github.com/cometbft/cometbft/p2p"
	"github.com/stretchr/testify/require"
)

func TestLoadConnKey(t *testing.T) {
	dir := t.TempDir()

	t.Run("loads an ed25519 node key file", func(t *testing.T) {
		want := cometcryptoed25519.GenPrivKey()
		path := filepath.Join(dir, "conn_key.json")
		require.NoError(t, (&cometp2p.NodeKey{PrivKey: want}).SaveAs(path))

		got, err := LoadConnKey(path)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("missing file is an error", func(t *testing.T) {
		_, err := LoadConnKey(filepath.Join(dir, "absent.json"))
		require.Error(t, err)
	})

	t.Run("malformed file is an error", func(t *testing.T) {
		path := filepath.Join(dir, "malformed.json")
		require.NoError(t, os.WriteFile(path, []byte("not json"), 0600))

		_, err := LoadConnKey(path)
		require.Error(t, err)
	})

	t.Run("undersized key is an error", func(t *testing.T) {
		for name, value := range map[string]string{
			"empty.json": "",
			"short.json": "AAAAAAAAAAAAAAAAAAAAAA==",
		} {
			path := filepath.Join(dir, name)
			content := fmt.Sprintf(`{"priv_key":{"type":"tendermint/PrivKeyEd25519","value":%q}}`, value)
			require.NoError(t, os.WriteFile(path, []byte(content), 0600))

			_, err := LoadConnKey(path)
			require.ErrorContains(t, err, "64", "%s must be rejected, not used as an identity", name)
		}
	})

	t.Run("non-ed25519 key is an error", func(t *testing.T) {
		path := filepath.Join(dir, "secp256k1.json")
		require.NoError(t, (&cometp2p.NodeKey{PrivKey: cometcryptosecp256k1.GenPrivKey()}).SaveAs(path))

		_, err := LoadConnKey(path)
		require.ErrorContains(t, err, "ed25519")
	})
}

func TestConnPubKeyFromHex(t *testing.T) {
	pubKey := cometcryptoed25519.GenPrivKey().PubKey()

	t.Run("decodes a hex encoded ed25519 public key", func(t *testing.T) {
		got, err := connPubKeyFromHex(hex.EncodeToString(pubKey.Bytes()))
		require.NoError(t, err)
		require.True(t, got.Equals(pubKey))
	})

	t.Run("rejects non-hex", func(t *testing.T) {
		_, err := connPubKeyFromHex("nothexatall")
		require.Error(t, err)
	})

	t.Run("rejects wrong length", func(t *testing.T) {
		_, err := connPubKeyFromHex(hex.EncodeToString([]byte("too short")))
		require.ErrorContains(t, err, "32")
	})

	t.Run("round-trips the public key of a connection key", func(t *testing.T) {
		privKey := cometcryptoed25519.GenPrivKey()

		got, err := connPubKeyFromHex(ConnPubKeyHex(privKey))
		require.NoError(t, err)
		require.True(t, got.Equals(privKey.PubKey()))
	})
}

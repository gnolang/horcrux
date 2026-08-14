package cmd

import (
	"bytes"
	"io"
	"path/filepath"
	"testing"

	"github.com/strangelove-ventures/horcrux/v3/signer"
	"github.com/stretchr/testify/require"
)

func TestCreateClusterKey(t *testing.T) {
	t.Run("creates a key and prints its public key", func(t *testing.T) {
		tmp := connKeyTestHome(t, "signMode: threshold\n")

		out := new(bytes.Buffer)
		cmd := rootCmd()
		cmd.SetOutput(out)
		cmd.SetArgs([]string{"create-cluster-key", "--home", tmp})
		require.NoError(t, cmd.Execute())

		keyFile := filepath.Join(tmp, "cluster_key.json")
		clusterKey, err := signer.LoadConnKey(keyFile)
		require.NoError(t, err)
		require.Contains(t, out.String(), signer.ConnPubKeyHex(clusterKey))
	})

	t.Run("refuses to overwrite an existing key", func(t *testing.T) {
		tmp := connKeyTestHome(t, "signMode: threshold\n")

		first := rootCmd()
		first.SetOutput(io.Discard)
		first.SetArgs([]string{"create-cluster-key", "--home", tmp})
		require.NoError(t, first.Execute())

		second := rootCmd()
		second.SetOutput(io.Discard)
		second.SetArgs([]string{"create-cluster-key", "--home", tmp})
		require.Error(t, second.Execute())
	})
}

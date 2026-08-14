package cmd

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/strangelove-ventures/horcrux/v3/signer"
	"github.com/stretchr/testify/require"
)

// connKeyTestHome returns a horcrux home directory holding the given config file
// contents, so loading it never reports a missing config.
func connKeyTestHome(t *testing.T, config string) string {
	t.Helper()

	home := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(home, "config.yaml"), []byte(config), 0600))

	return home
}

func TestLoadConfiguredConnKey(t *testing.T) {
	t.Run("no configured key leaves the identity ephemeral", func(t *testing.T) {
		key, err := loadConfiguredConnKey(signer.RuntimeConfig{HomeDir: t.TempDir()})
		require.NoError(t, err)
		require.Nil(t, key)
	})

	t.Run("a configured key is loaded", func(t *testing.T) {
		home := t.TempDir()
		created, err := signer.CreateConnKey(filepath.Join(home, "conn_key.json"))
		require.NoError(t, err)

		key, err := loadConfiguredConnKey(signer.RuntimeConfig{
			HomeDir: home,
			Config:  signer.Config{ConnKeyFile: "conn_key.json"},
		})
		require.NoError(t, err)
		require.Equal(t, created, key)
	})

	// A configured key that cannot be loaded must stop startup: falling back to an
	// ephemeral identity would silently drop the authentication the operator asked
	// for, and every chain node would reject the cosigner instead.
	t.Run("an unloadable configured key is an error, never a fallback", func(t *testing.T) {
		home := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(home, "malformed.json"), []byte("{"), 0600))

		for name, file := range map[string]string{
			"missing":   "absent.json",
			"malformed": "malformed.json",
		} {
			key, err := loadConfiguredConnKey(signer.RuntimeConfig{
				HomeDir: home,
				Config:  signer.Config{ConnKeyFile: file},
			})
			require.Error(t, err, "%s key must fail startup", name)
			require.Nil(t, key, "%s key must not yield an identity", name)
		}
	})
}

func TestCreateConnKey(t *testing.T) {
	t.Run("creates a key in the home directory and prints its public key", func(t *testing.T) {
		tmp := connKeyTestHome(t, "signMode: threshold\n")

		out := new(bytes.Buffer)
		cmd := rootCmd()
		cmd.SetOut(out)
		cmd.SetArgs([]string{"create-conn-key", "--home", tmp})
		require.NoError(t, cmd.Execute())

		keyFile := filepath.Join(tmp, "conn_key.json")
		connKey, err := signer.LoadConnKey(keyFile)
		require.NoError(t, err)

		stat, err := os.Stat(keyFile)
		require.NoError(t, err)
		require.Equal(t, fs.FileMode(0600), stat.Mode().Perm())

		// The printed key is what an operator authorizes on each chain node.
		require.Contains(t, out.String(), signer.ConnPubKeyHex(connKey))
	})

	t.Run("refuses to overwrite an existing key", func(t *testing.T) {
		tmp := connKeyTestHome(t, "signMode: threshold\n")

		first := rootCmd()
		first.SetOut(io.Discard)
		first.SetArgs([]string{"create-conn-key", "--home", tmp})
		require.NoError(t, first.Execute())

		keyFile := filepath.Join(tmp, "conn_key.json")
		connKey, err := signer.LoadConnKey(keyFile)
		require.NoError(t, err)

		second := rootCmd()
		second.SetOut(io.Discard)
		second.SetArgs([]string{"create-conn-key", "--home", tmp})
		require.Error(t, second.Execute())

		reloaded, err := signer.LoadConnKey(keyFile)
		require.NoError(t, err)
		require.Equal(t, connKey, reloaded)
	})

	t.Run("creates the key where start will look for it when keyDir is set", func(t *testing.T) {
		keyDir := t.TempDir()
		tmp := connKeyTestHome(t, "keyDir: "+keyDir+"\n")

		cmd := rootCmd()
		cmd.SetOut(io.Discard)
		cmd.SetArgs([]string{"create-conn-key", "--home", tmp})
		require.NoError(t, cmd.Execute())

		_, err := signer.LoadConnKey(filepath.Join(keyDir, "conn_key.json"))
		require.NoError(t, err)
	})

	t.Run("honors a configured connKeyFile", func(t *testing.T) {
		tmp := connKeyTestHome(t, "connKeyFile: custom_conn.json\n")

		cmd := rootCmd()
		cmd.SetOut(io.Discard)
		cmd.SetArgs([]string{"create-conn-key", "--home", tmp})
		require.NoError(t, cmd.Execute())

		_, err := signer.LoadConnKey(filepath.Join(tmp, "custom_conn.json"))
		require.NoError(t, err)
	})
}

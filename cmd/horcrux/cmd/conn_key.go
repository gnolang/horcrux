package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/v3/signer"
)

// defaultConnKeyFile is the file name for a connection key created when no
// connKeyFile is configured.
const defaultConnKeyFile = "conn_key.json"

// loadConfiguredConnKey loads the persistent connection identity when one is
// configured. It returns a nil key when connKeyFile is unset, and an error rather
// than an ephemeral identity when a configured key cannot be loaded: silently
// falling back would drop the authentication the operator asked for.
func loadConfiguredConnKey(cfg signer.RuntimeConfig) (cometcryptoed25519.PrivKey, error) {
	connKeyFile := cfg.ConnKeyFilePath()
	if connKeyFile == "" {
		return nil, nil
	}

	return signer.LoadConnKey(connKeyFile)
}

// createConnKeyCmd is a cobra command for creating the connection key that
// authenticates this cosigner to the chain nodes it signs for.
func createConnKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create-conn-key",
		Args:  cobra.NoArgs,
		Short: "Create a connection key to authenticate to chain nodes",
		Long: `Create the ed25519 key this cosigner presents when connecting to a chain node's priv
validator listener. A chain node that authorizes signers by public key can then admit
this cosigner, which is impossible without a persistent key because the cosigner
otherwise presents a new public key on every start.

The key is a per-cosigner identity rather than shared cluster material, so run this on
each cosigner and authorize every cosigner's public key on each chain node.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Without a configured connKeyFile the key goes where that setting
			// would resolve it, so the printed instruction below is accurate.
			keyFile := config.ConnKeyFilePath()
			if keyFile == "" {
				keyFile = filepath.Join(config.KeyDirectory(), defaultConnKeyFile)
			}

			if _, err := os.Stat(keyFile); err == nil {
				return fmt.Errorf("connection key already exists: %s", keyFile)
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("unexpected error checking for connection key (%s): %w", keyFile, err)
			}

			if err := os.MkdirAll(filepath.Dir(keyFile), 0700); err != nil {
				return err
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			connKey, err := signer.CreateConnKey(keyFile)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Created connection key: %s\n", keyFile)
			fmt.Fprintf(out, "Connection public key (hex): %s\n", signer.ConnPubKeyHex(connKey))

			if config.Config.ConnKeyFile == "" {
				fmt.Fprintf(
					out,
					"\nAuthorize this public key on each chain node, then set `connKeyFile: %s` in %s.\n",
					defaultConnKeyFile, config.ConfigFile,
				)
			}

			return nil
		},
	}
}

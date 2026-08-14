package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/v3/signer"
)

// defaultClusterKeyFile is the file name for a cluster identity key created when
// no clusterKeyFile is configured.
const defaultClusterKeyFile = "cluster_key.json"

// createClusterKeyCmd creates the ed25519 identity this cosigner uses for mutual
// TLS with its peer cosigners.
func createClusterKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create-cluster-key",
		Args:  cobra.NoArgs,
		Short: "Create a cluster key for cosigner mutual TLS",
		Long: `Create the ed25519 key this cosigner presents to its peer cosigners for mutual TLS
on the cluster transport (raft + cosigner RPC).

The key is a per-cosigner identity. Run this on each cosigner, set clusterKeyFile in
its config, and list every cosigner's public key as tlsPubKey on the matching
cosigners entry across the cluster.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			keyFile := config.ClusterKeyFilePath()
			if keyFile == "" {
				keyFile = filepath.Join(config.KeyDirectory(), defaultClusterKeyFile)
			}

			if _, err := os.Stat(keyFile); err == nil {
				return fmt.Errorf("cluster key already exists: %s", keyFile)
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("unexpected error checking for cluster key (%s): %w", keyFile, err)
			}

			if err := os.MkdirAll(filepath.Dir(keyFile), 0700); err != nil {
				return err
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			clusterKey, err := signer.CreateConnKey(keyFile)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Created cluster key: %s\n", keyFile)
			fmt.Fprintf(out, "Cluster public key (hex): %s\n", signer.ConnPubKeyHex(clusterKey))
			fmt.Fprintf(
				out,
				"\nSet `clusterKeyFile` in this cosigner's config, and add this key as `tlsPubKey`\n"+
					"on this cosigner's entry in every cluster member's config.\n",
			)

			return nil
		},
	}
}

package signer_test

import (
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/strangelove-ventures/horcrux/v3/signer"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

const testChainID = "test"

func TestConnKeyFilePath(t *testing.T) {
	homeDir := t.TempDir()
	keyDir := t.TempDir()

	testCases := []struct {
		name     string
		config   signer.Config
		expected string
	}{
		{
			name:     "unset connKeyFile",
			config:   signer.Config{},
			expected: "",
		},
		{
			name:     "relative path resolves against home dir",
			config:   signer.Config{ConnKeyFile: "conn_key.json"},
			expected: filepath.Join(homeDir, "conn_key.json"),
		},
		{
			name:     "relative path resolves against key dir when set",
			config:   signer.Config{ConnKeyFile: "conn_key.json", PrivValKeyDir: &keyDir},
			expected: filepath.Join(keyDir, "conn_key.json"),
		},
		{
			name:     "empty key dir falls back to the home dir",
			config:   signer.Config{ConnKeyFile: "conn_key.json", PrivValKeyDir: new(string)},
			expected: filepath.Join(homeDir, "conn_key.json"),
		},
		{
			name:     "absolute path is used as-is",
			config:   signer.Config{ConnKeyFile: filepath.Join(keyDir, "elsewhere.json")},
			expected: filepath.Join(keyDir, "elsewhere.json"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := signer.RuntimeConfig{HomeDir: homeDir, Config: tc.config}
			require.Equal(t, tc.expected, c.ConnKeyFilePath())
		})
	}
}

func TestChainNodeConnPubKey(t *testing.T) {
	pubKey := cometcryptoed25519.GenPrivKey().PubKey()

	t.Run("no pin configured", func(t *testing.T) {
		got, err := signer.ChainNode{PrivValAddr: "tcp://127.0.0.1:1234"}.ConnPubKey()
		require.NoError(t, err)
		require.Nil(t, got)
	})

	t.Run("pinned node returns the expected public key", func(t *testing.T) {
		cn := signer.ChainNode{
			PrivValAddr:   "tcp://127.0.0.1:1234",
			ConnPubKeyHex: hex.EncodeToString(pubKey.Bytes()),
		}

		got, err := cn.ConnPubKey()
		require.NoError(t, err)
		require.True(t, got.Equals(pubKey))
	})

	t.Run("malformed pin is an error", func(t *testing.T) {
		cn := signer.ChainNode{
			PrivValAddr:   "tcp://127.0.0.1:1234",
			ConnPubKeyHex: "beefbeef",
		}

		_, err := cn.ConnPubKey()
		require.Error(t, err)
	})

	t.Run("validate rejects a malformed pin", func(t *testing.T) {
		cns := signer.ChainNodes{{
			PrivValAddr:   "tcp://127.0.0.1:1234",
			ConnPubKeyHex: "beefbeef",
		}}

		require.Error(t, cns.Validate())
	})
}

func TestConfigYamlConnAuth(t *testing.T) {
	pubKey := cometcryptoed25519.GenPrivKey().PubKey()

	raw := fmt.Sprintf(`signMode: threshold
connKeyFile: conn_key.json
chainNodes:
- privValAddr: tcp://10.168.0.1:1234
  connPubKey: %s
- privValAddr: tcp://10.168.0.2:1234
`, hex.EncodeToString(pubKey.Bytes()))

	var c signer.Config
	require.NoError(t, yaml.Unmarshal([]byte(raw), &c))

	require.Equal(t, "conn_key.json", c.ConnKeyFile)
	require.Len(t, c.ChainNodes, 2)

	pinned, err := c.ChainNodes[0].ConnPubKey()
	require.NoError(t, err)
	require.True(t, pinned.Equals(pubKey))

	unpinned, err := c.ChainNodes[1].ConnPubKey()
	require.NoError(t, err)
	require.Nil(t, unpinned)
}

func TestConfigYamlLeaderOnlyChainNodeConnections(t *testing.T) {
	raw := `signMode: threshold
thresholdMode:
  threshold: 2
  leaderOnlyChainNodeConnections: true
chainNodes:
- privValAddr: tcp://10.168.0.1:1234
`

	var c signer.Config
	require.NoError(t, yaml.Unmarshal([]byte(raw), &c))
	require.True(t, c.ThresholdModeConfig.LeaderOnlyChainNodeConnections)

	// The flag defaults to false when absent.
	var d signer.Config
	require.NoError(t, yaml.Unmarshal([]byte("thresholdMode:\n  threshold: 2\n"), &d))
	require.False(t, d.ThresholdModeConfig.LeaderOnlyChainNodeConnections)
}

func TestClusterPeerPubKeys(t *testing.T) {
	k1 := cometcryptoed25519.GenPrivKey().PubKey()
	k2 := cometcryptoed25519.GenPrivKey().PubKey()

	cfg := &signer.ThresholdModeConfig{
		Cosigners: signer.CosignersConfig{
			{ShardID: 1, P2PAddr: "tcp://10.0.0.1:2222", TLSPubKey: hex.EncodeToString(k1.Bytes())},
			{ShardID: 2, P2PAddr: "tcp://10.0.0.2:2222", TLSPubKey: hex.EncodeToString(k2.Bytes())},
		},
	}

	require.False(t, cfg.ClusterTLSEnabled())
	cfg.ClusterKeyFile = "cluster_key.json"
	require.True(t, cfg.ClusterTLSEnabled())

	keys, err := cfg.ClusterPeerPubKeys()
	require.NoError(t, err)
	require.Len(t, keys, 2)
	require.True(t, keys[0].Equals(k1))
	require.True(t, keys[1].Equals(k2))

	// A cosigner missing/invalid tlsPubKey makes the allowlist incomplete.
	cfg.Cosigners[1].TLSPubKey = ""
	_, err = cfg.ClusterPeerPubKeys()
	require.Error(t, err)
}

func TestValidateClusterTLSConfig(t *testing.T) {
	k1 := hex.EncodeToString(cometcryptoed25519.GenPrivKey().PubKey().Bytes())
	k2 := hex.EncodeToString(cometcryptoed25519.GenPrivKey().PubKey().Bytes())

	mkConfig := func(tls1, tls2 string) signer.Config {
		return signer.Config{
			ThresholdModeConfig: &signer.ThresholdModeConfig{
				Threshold:      2,
				ClusterKeyFile: "cluster_key.json",
				GRPCTimeout:    "500ms",
				RaftTimeout:    "500ms",
				Cosigners: signer.CosignersConfig{
					{ShardID: 1, P2PAddr: "tcp://10.0.0.1:2222", TLSPubKey: tls1},
					{ShardID: 2, P2PAddr: "tcp://10.0.0.2:2222", TLSPubKey: tls2},
				},
			},
		}
	}

	t.Run("distinct tlsPubKeys validate", func(t *testing.T) {
		c := mkConfig(k1, k2)
		require.NoError(t, c.ValidateThresholdModeConfig())
	})

	t.Run("missing tlsPubKey is rejected", func(t *testing.T) {
		c := mkConfig(k1, "")
		require.Error(t, c.ValidateThresholdModeConfig())
	})

	t.Run("duplicate tlsPubKey is rejected", func(t *testing.T) {
		c := mkConfig(k1, k1)
		require.Error(t, c.ValidateThresholdModeConfig())
	})
}

func TestValidateSingleSignerConfig(t *testing.T) {
	type testCase struct {
		name      string
		config    signer.Config
		expectErr error
	}

	testCases := []testCase{
		{
			name: "valid config",
			config: signer.Config{
				ChainNodes: []signer.ChainNode{
					{
						PrivValAddr: "tcp://127.0.0.1:1234",
					},
				},
			},
			expectErr: nil,
		},
		{
			name: "invalid node address",
			config: signer.Config{
				ChainNodes: []signer.ChainNode{
					{
						PrivValAddr: "abc://\\invalid_addr",
					},
				},
			},
			expectErr: &url.Error{Op: "parse", URL: "abc://\\invalid_addr", Err: url.InvalidHostError("\\")},
		},
	}

	for _, tc := range testCases {
		err := tc.config.ValidateSingleSignerConfig()
		if tc.expectErr == nil {
			require.NoError(t, err, tc.name)
		} else {
			require.Error(t, err, tc.name)
			require.EqualError(t, err, tc.expectErr.Error(), tc.name)
		}
	}
}

func TestValidateThresholdModeConfig(t *testing.T) {
	type testCase struct {
		name      string
		config    signer.Config
		expectErr error
	}

	testCases := []testCase{
		{
			name: "valid config",
			config: signer.Config{
				ThresholdModeConfig: &signer.ThresholdModeConfig{
					Threshold:   2,
					RaftTimeout: "1000ms",
					GRPCTimeout: "1000ms",
					Cosigners: signer.CosignersConfig{
						{
							ShardID: 1,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShardID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShardID: 3,
							P2PAddr: "tcp://127.0.0.1:2224",
						},
					},
				},
				ChainNodes: []signer.ChainNode{
					{
						PrivValAddr: "tcp://127.0.0.1:1234",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:2345",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:3456",
					},
				},
			},
			expectErr: nil,
		},
		{
			name: "no cosigner config",
			config: signer.Config{
				ChainNodes: []signer.ChainNode{
					{
						PrivValAddr: "tcp://127.0.0.1:1234",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:2345",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:3456",
					},
				},
			},
			expectErr: fmt.Errorf("cosigner config can't be empty"),
		},
		{
			name: "invalid p2p listen",
			config: signer.Config{
				ThresholdModeConfig: &signer.ThresholdModeConfig{
					Threshold:   2,
					RaftTimeout: "1000ms",
					GRPCTimeout: "1000ms",
					Cosigners: signer.CosignersConfig{
						{
							ShardID: 1,
							P2PAddr: ":2222",
						},
						{
							ShardID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShardID: 3,
							P2PAddr: "tcp://127.0.0.1:2224",
						},
					},
				},
				ChainNodes: []signer.ChainNode{
					{
						PrivValAddr: "tcp://127.0.0.1:1234",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:2345",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:3456",
					},
				},
			},
			expectErr: fmt.Errorf("failed to parse cosigner (shard ID: 1) p2p address: %w", &url.Error{
				Op:  "parse",
				URL: ":2222",
				Err: fmt.Errorf("missing protocol scheme"),
			}),
		},
		{
			name: "not enough cosigners",
			config: signer.Config{
				ThresholdModeConfig: &signer.ThresholdModeConfig{
					Threshold:   3,
					RaftTimeout: "1000ms",
					GRPCTimeout: "1000ms",
					Cosigners: signer.CosignersConfig{
						{
							ShardID: 1,
							P2PAddr: "tcp://127.0.0.1:2222",
						},
						{
							ShardID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
					},
				},
				ChainNodes: []signer.ChainNode{
					{
						PrivValAddr: "tcp://127.0.0.1:1234",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:2345",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:3456",
					},
				},
			},
			expectErr: fmt.Errorf("number of shards (2) must be greater or equal to threshold (3)"),
		},
		{
			name: "invalid raft timeout",
			config: signer.Config{
				ThresholdModeConfig: &signer.ThresholdModeConfig{
					Threshold:   2,
					GRPCTimeout: "1000ms",
					RaftTimeout: "1000",
					Cosigners: signer.CosignersConfig{
						{
							ShardID: 1,
							P2PAddr: "tcp://127.0.0.1:2222",
						},
						{
							ShardID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShardID: 3,
							P2PAddr: "tcp://127.0.0.1:2224",
						},
					},
				},
				ChainNodes: []signer.ChainNode{
					{
						PrivValAddr: "tcp://127.0.0.1:1234",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:2345",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:3456",
					},
				},
			},
			expectErr: fmt.Errorf("invalid raftTimeout: %w", fmt.Errorf("time: missing unit in duration \"1000\"")),
		},
		{
			name: "invalid grpc timeout",
			config: signer.Config{
				ThresholdModeConfig: &signer.ThresholdModeConfig{
					Threshold:   2,
					GRPCTimeout: "1000",
					RaftTimeout: "1000ms",
					Cosigners: signer.CosignersConfig{
						{
							ShardID: 1,
							P2PAddr: "tcp://127.0.0.1:2222",
						},
						{
							ShardID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShardID: 3,
							P2PAddr: "tcp://127.0.0.1:2224",
						},
					},
				},
				ChainNodes: []signer.ChainNode{
					{
						PrivValAddr: "tcp://127.0.0.1:1234",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:2345",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:3456",
					},
				},
			},
			expectErr: fmt.Errorf("invalid grpcTimeout: %w", fmt.Errorf("time: missing unit in duration \"1000\"")),
		},
		{
			name: "invalid node address",
			config: signer.Config{
				ThresholdModeConfig: &signer.ThresholdModeConfig{
					Threshold:   2,
					RaftTimeout: "1000ms",
					GRPCTimeout: "1000ms",
					Cosigners: signer.CosignersConfig{
						{
							ShardID: 1,
							P2PAddr: "tcp://127.0.0.1:2222",
						},
						{
							ShardID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShardID: 3,
							P2PAddr: "tcp://127.0.0.1:2224",
						},
					},
				},
				ChainNodes: []signer.ChainNode{
					{
						PrivValAddr: "abc://\\invalid_addr",
					},
				},
			},
			expectErr: &url.Error{Op: "parse", URL: "abc://\\invalid_addr", Err: url.InvalidHostError("\\")},
		},
	}

	for _, tc := range testCases {
		err := tc.config.ValidateThresholdModeConfig()
		if tc.expectErr == nil {
			require.NoError(t, err, tc.name)
		} else {
			require.Error(t, err, tc.name)
			require.EqualError(t, err, tc.expectErr.Error(), tc.name)
		}
	}
}

func TestRuntimeConfigKeyFilePath(t *testing.T) {
	dir := t.TempDir()
	c := signer.RuntimeConfig{
		HomeDir: dir,
	}

	require.Equal(t, filepath.Join(dir, fmt.Sprintf("%s_shard.json", testChainID)), c.KeyFilePathCosigner(testChainID))
	require.Equal(
		t,
		filepath.Join(dir, fmt.Sprintf("%s_priv_validator_key.json", testChainID)),
		c.KeyFilePathSingleSigner(testChainID),
	)
}

func TestRuntimeConfigPrivValStateFile(t *testing.T) {
	dir := t.TempDir()
	c := signer.RuntimeConfig{
		StateDir: dir,
	}

	require.Equal(t, filepath.Join(dir, "chain-1_priv_validator_state.json"), c.PrivValStateFile("chain-1"))
}

func TestRuntimeConfigWriteConfigFile(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.yaml")
	c := signer.RuntimeConfig{
		ConfigFile: configFile,
		Config: signer.Config{
			SignMode: signer.SignModeThreshold,
			ThresholdModeConfig: &signer.ThresholdModeConfig{
				Threshold:   2,
				RaftTimeout: "1000ms",
				GRPCTimeout: "1000ms",
				Cosigners: signer.CosignersConfig{
					{
						ShardID: 1,
						P2PAddr: "tcp://127.0.0.1:2222",
					},
					{
						ShardID: 2,
						P2PAddr: "tcp://127.0.0.1:2223",
					},
					{
						ShardID: 3,
						P2PAddr: "tcp://127.0.0.1:2224",
					},
				},
			},
			ChainNodes: []signer.ChainNode{
				{
					PrivValAddr: "tcp://127.0.0.1:1234",
				},
				{
					PrivValAddr: "tcp://127.0.0.1:2345",
				},
				{
					PrivValAddr: "tcp://127.0.0.1:3456",
				},
			},
			MaxReadSize: 1024 * 1024,
		},
	}

	require.NoError(t, c.WriteConfigFile())
	configYamlBz, err := os.ReadFile(configFile)
	require.NoError(t, err)
	require.Equal(t, `signMode: threshold
thresholdMode:
  threshold: 2
  cosigners:
  - shardID: 1
    p2pAddr: tcp://127.0.0.1:2222
  - shardID: 2
    p2pAddr: tcp://127.0.0.1:2223
  - shardID: 3
    p2pAddr: tcp://127.0.0.1:2224
  grpcTimeout: 1000ms
  raftTimeout: 1000ms
chainNodes:
- privValAddr: tcp://127.0.0.1:1234
- privValAddr: tcp://127.0.0.1:2345
- privValAddr: tcp://127.0.0.1:3456
debugAddr: ""
grpcAddr: ""
maxReadSize: 1048576
`, string(configYamlBz))
}

func TestRuntimeConfigKeyFileExists(t *testing.T) {
	dir := t.TempDir()
	c := signer.RuntimeConfig{
		HomeDir: dir,
	}

	// Test cosigner
	keyFile, err := c.KeyFileExistsCosigner(testChainID)
	require.Error(t, err)

	require.Equal(t, fmt.Errorf(
		"file doesn't exist at path (%s): %w",
		keyFile,
		&fs.PathError{
			Op:   "stat",
			Path: keyFile,
			Err:  fmt.Errorf("no such file or directory"),
		},
	).Error(), err.Error())

	err = os.WriteFile(keyFile, []byte{}, 0600)
	require.NoError(t, err)

	_, err = c.KeyFileExistsCosigner(testChainID)
	require.NoError(t, err)

	// Test single signer
	keyFile, err = c.KeyFileExistsSingleSigner(testChainID)
	require.Error(t, err)

	require.Equal(t, fmt.Errorf(
		"file doesn't exist at path (%s): %w",
		keyFile,
		&fs.PathError{
			Op:   "stat",
			Path: keyFile,
			Err:  fmt.Errorf("no such file or directory"),
		},
	).Error(), err.Error())

	err = os.WriteFile(keyFile, []byte{}, 0600)
	require.NoError(t, err)

	_, err = c.KeyFileExistsSingleSigner(testChainID)
	require.NoError(t, err)
}

func TestThresholdModeConfigLeaderElectMultiAddress(t *testing.T) {
	c := &signer.ThresholdModeConfig{
		Threshold:   2,
		RaftTimeout: "1000ms",
		GRPCTimeout: "1000ms",
		Cosigners: signer.CosignersConfig{
			{
				ShardID: 1,
				P2PAddr: "tcp://127.0.0.1:2222",
			},
			{
				ShardID: 2,
				P2PAddr: "tcp://127.0.0.1:2223",
			},
			{
				ShardID: 3,
				P2PAddr: "tcp://127.0.0.1:2224",
			},
		},
	}

	multiAddr, err := c.LeaderElectMultiAddress()
	require.NoError(t, err)
	require.Equal(t, "multi:///127.0.0.1:2222,127.0.0.1:2223,127.0.0.1:2224", multiAddr)
}

func TestCosignerRSAPubKeysConfigValidate(t *testing.T) {
	type testCase struct {
		name      string
		cosigners signer.CosignersConfig
		expectErr error
	}
	testCases := []testCase{
		{
			name: "valid config",
			cosigners: signer.CosignersConfig{
				{
					ShardID: 1,
					P2PAddr: "tcp://127.0.0.1:2222",
				},
				{
					ShardID: 2,
					P2PAddr: "tcp://127.0.0.1:2223",
				},
				{
					ShardID: 3,
					P2PAddr: "tcp://127.0.0.1:2224",
				},
			},
			expectErr: nil,
		},
		{
			name: "too many cosigners",
			cosigners: signer.CosignersConfig{
				{
					ShardID: 2,
					P2PAddr: "tcp://127.0.0.1:2223",
				},
				{
					ShardID: 3,
					P2PAddr: "tcp://127.0.0.1:2224",
				},
			},
			expectErr: fmt.Errorf("cosigner shard ID 3 in args is out of range, must be between 1 and 2, inclusive"),
		},
		{
			name: "duplicate cosigner",
			cosigners: signer.CosignersConfig{
				{
					ShardID: 2,
					P2PAddr: "tcp://127.0.0.1:2223",
				},
				{
					ShardID: 2,
					P2PAddr: "tcp://127.0.0.1:2223",
				},
			},
			expectErr: fmt.Errorf(
				"found duplicate cosigner shard ID(s) in args: map[2:[tcp://127.0.0.1:2223 tcp://127.0.0.1:2223]]",
			),
		},
	}

	for _, tc := range testCases {
		err := tc.cosigners.Validate()
		if tc.expectErr == nil {
			require.NoError(t, err, tc.name)
		} else {
			require.Error(t, err, tc.name)
			require.EqualError(t, err, tc.expectErr.Error(), tc.name)
		}
	}
}

func TestCosignersFromFlag(t *testing.T) {
	type testCase struct {
		name      string
		cosigners []string
		expectErr error
	}

	testCases := []testCase{
		{
			name:      "valid cosigners flag",
			cosigners: []string{"tcp://127.0.0.1:2222", "tcp://127.0.0.1:2223"},
			expectErr: nil,
		},
	}

	for _, tc := range testCases {
		_, err := signer.CosignersFromFlag(tc.cosigners)
		if tc.expectErr == nil {
			require.NoError(t, err, tc.name)
		} else {
			require.Error(t, err, tc.name)
			require.EqualError(t, err, tc.expectErr.Error(), tc.name)
		}
	}
}

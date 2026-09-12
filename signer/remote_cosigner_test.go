package signer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A peer cosigner's gRPC target must use passthrough resolution: the default
// dns resolver refuses to re-resolve for 30 seconds after a failure
// (MinResolutionInterval), so a peer that restarts with a new IP — a container
// restart, an instance replacement — stays unreachable well past its actual
// downtime. Passthrough hands the hostname to the dialer, which resolves it
// fresh on every connection attempt.
func TestPeerGRPCTargetUsesPassthroughResolution(t *testing.T) {
	require.Equal(t, "passthrough:///cosigner-2:2222", peerGRPCTarget("tcp://cosigner-2:2222"))
	require.Equal(t, "passthrough:///10.0.0.7:2222", peerGRPCTarget("10.0.0.7:2222"))
}

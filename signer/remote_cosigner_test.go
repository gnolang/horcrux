package signer

import (
	"context"
	"testing"
	"time"

	"github.com/strangelove-ventures/horcrux/v3/signer/proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
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

type signBlockResponseClient struct {
	proto.CosignerClient
	response *proto.SignBlockResponse
}

func (c signBlockResponseClient) SignBlock(
	context.Context, *proto.SignBlockRequest, ...grpc.CallOption,
) (*proto.SignBlockResponse, error) {
	return c.response, nil
}

func TestRemoteCosignerSignTimestamp(t *testing.T) {
	requestTimestamp := time.Date(2026, time.September, 14, 12, 0, 0, 123456789, time.UTC)
	cachedTimestamp := requestTimestamp.Add(-2 * time.Millisecond)

	for _, tc := range []struct {
		name              string
		responseTimestamp int64
		wantTimestamp     time.Time
	}{
		{
			name:          "legacy leader omits timestamp",
			wantTimestamp: requestTimestamp,
		},
		{
			name:              "leader signs requested timestamp",
			responseTimestamp: requestTimestamp.UnixNano(),
			wantTimestamp:     requestTimestamp,
		},
		{
			name:              "leader returns cached timestamp",
			responseTimestamp: cachedTimestamp.UnixNano(),
			wantTimestamp:     cachedTimestamp,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := &proto.SignBlockResponse{
				Signature:        []byte("vote signature"),
				VoteExtSignature: []byte("extension signature"),
				Timestamp:        tc.responseTimestamp,
			}
			cosigner := &RemoteCosigner{client: signBlockResponseClient{response: response}}
			result, err := cosigner.Sign(context.Background(), CosignerSignBlockRequest{
				ChainID: testChainID,
				Block:   &Block{Timestamp: requestTimestamp},
			})
			require.NoError(t, err)
			require.True(t, tc.wantTimestamp.Equal(result.Timestamp),
				"want timestamp %s, got %s", tc.wantTimestamp, result.Timestamp)
			require.Equal(t, response.Signature, result.Signature)
			require.Equal(t, response.VoteExtSignature, result.VoteExtensionSignature)
		})
	}
}

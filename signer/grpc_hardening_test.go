package signer

import (
	"context"
	"testing"

	"github.com/strangelove-ventures/horcrux/v3/signer/proto"
	"github.com/stretchr/testify/require"
)

// The gRPC boundary must reject malformed input with an error instead of
// dereferencing a nil field or converting a short slice to a UUID array (both of
// which panic and, without a recovery interceptor, take the process down).

func TestSignBlockRejectsNilBlock(t *testing.T) {
	s := &CosignerGRPCServer{}
	_, err := s.SignBlock(context.Background(), &proto.SignBlockRequest{ChainID: "x"})
	require.Error(t, err)
}

func TestSetNoncesAndSignRejectsNilHrst(t *testing.T) {
	s := &CosignerGRPCServer{}
	_, err := s.SetNoncesAndSign(context.Background(), &proto.SetNoncesAndSignRequest{
		Uuid: make([]byte, uuidLen),
	})
	require.Error(t, err)
}

func TestSetNoncesAndSignRejectsShortUUID(t *testing.T) {
	s := &CosignerGRPCServer{}
	_, err := s.SetNoncesAndSign(context.Background(), &proto.SetNoncesAndSignRequest{
		Hrst: &proto.HRST{},
		Uuid: []byte("short"),
	})
	require.Error(t, err)
}

func TestGetNoncesRejectsShortUUID(t *testing.T) {
	s := &CosignerGRPCServer{}
	_, err := s.GetNonces(context.Background(), &proto.GetNoncesRequest{
		Uuids: [][]byte{[]byte("short")},
	})
	require.Error(t, err)
}

func TestCombineSignaturesRejectsShortPartial(t *testing.T) {
	s := &ThresholdSignerSoft{total: 2}
	_, err := s.CombineSignatures([]PartialSignature{{ID: 1, Signature: []byte("short")}})
	require.Error(t, err)
}

// The node-facing gRPC handlers must reject an invalid chain ID before it reaches
// a file path (single-signer traversal) or a Prometheus metric label (cardinality).
func TestRemoteSignerPubKeyRejectsBadChainID(t *testing.T) {
	s := &RemoteSignerGRPCServer{}
	_, err := s.PubKey(context.Background(), &proto.PubKeyRequest{ChainId: "../../etc/passwd"})
	require.Error(t, err)
}

func TestRemoteSignerSignRejectsBadChainID(t *testing.T) {
	s := &RemoteSignerGRPCServer{}
	_, err := s.Sign(context.Background(), &proto.SignBlockRequest{ChainID: "a/b", Block: &proto.Block{}})
	require.Error(t, err)
}

func TestRemoteSignerSignRejectsNilBlock(t *testing.T) {
	s := &RemoteSignerGRPCServer{}
	_, err := s.Sign(context.Background(), &proto.SignBlockRequest{ChainID: "chain-1"})
	require.Error(t, err)
}

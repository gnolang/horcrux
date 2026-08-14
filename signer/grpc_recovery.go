package signer

import (
	"context"
	"runtime/debug"

	cometlog "github.com/cometbft/cometbft/libs/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// recoveryUnaryInterceptor converts a panic in any gRPC handler into an error so
// that malformed or hostile input cannot take the process down. A crash here is a
// validator liveness failure, so this is a backstop behind explicit per-handler
// input validation, not a replacement for it.
func recoveryUnaryInterceptor(logger cometlog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error(
					"recovered from panic in gRPC handler",
					"method", info.FullMethod,
					"panic", r,
					"stack", string(debug.Stack()),
				)
				err = status.Errorf(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}

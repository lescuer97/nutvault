package routes

import (
	"context"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	sig "nutmix_remote_signer/gen"
)

const signatorySchemaVersion = "x-signatory-schema-version"

func SchemaVersion() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {
		metadataValues, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.InvalidArgument, "missing metadata")
		}

		values := metadataValues.Get(signatorySchemaVersion)
		if len(values) == 0 {
			return nil, status.Error(codes.InvalidArgument, "missing signatory schema version")
		}

		versionNum, err := strconv.Atoi(values[0])
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid signatory schema version")
		}

		if versionNum < int(sig.Constants_CONSTANTS_VERSION) {
			return nil, status.Error(codes.InvalidArgument, "signatory schema version too old")
		}

		return handler(ctx, req)
	}
}

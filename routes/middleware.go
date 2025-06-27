package routes

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"nutmix_remote_signer/database"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func AuthMiddleware(db database.SqliteDB) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		// check the auth token
		tokenStr := md.Get("auth-token")
		if len(tokenStr) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing authToken")
		}
		token := tokenStr[0]

		authToken, err := db.GetAuthTokenByToken(token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "Token does not exists")
		}

		if !authToken.Active {
			return nil, status.Error(codes.Unauthenticated, "Inactive auth token")
		}
		// calculate a random value from the id and npub together
		unitSha256 := sha256.Sum256([]byte(authToken.AccountId + authToken.Id))
		derivationInteger := binary.BigEndian.Uint32(unitSha256[:4])

		// Add user info to context
		ctx = context.WithValue(ctx, "derivation", derivationInteger)

		return handler(ctx, req)
	}
}

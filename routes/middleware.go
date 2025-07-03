package routes

import (
	"context"
	"log/slog"
	"nutmix_remote_signer/database"
	"nutmix_remote_signer/signer"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const signerInfoKey = "signerInfo"

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
			slog.Warn("error getting a token", slog.String("error", err.Error()))
			return nil, status.Error(codes.Unauthenticated, "Token does not exists")
		}

		account, err := db.GetAccountById(authToken.AccountId)
		if err != nil {
			slog.Warn("Could not get account", slog.String("error", err.Error()))
			return nil, status.Error(codes.Unauthenticated, "acccount does not exists")
		}
		if account == nil {
			return nil, status.Error(codes.Unauthenticated, "No account")
		}

		if !authToken.Active {
			return nil, status.Error(codes.Unauthenticated, "Inactive auth token")
		}

		// FIX: Verify signature of the account

		signerInfo := signer.SignerInfo{
			AccountId:  authToken.AccountId,
			Derivation: uint32(account.Derivation),
		}
		// Add user info to context
		ctx = context.WithValue(ctx, signerInfoKey, signerInfo)

		return handler(ctx, req)
	}
}

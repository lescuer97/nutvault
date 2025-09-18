package routes

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"log"
	"log/slog"
	"nutmix_remote_signer/database"
	"nutmix_remote_signer/signer"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const signerInfoKey = "signerInfo"

func AuthMiddleware(db database.SqliteDB) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {
		// Extract peer TLS info
		p, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "no peer info")
		}

		tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "no TLS info")
		}

		var leaf *x509.Certificate
		log.Printf("\n tlsInfo.State.VerifiedChains. %+v", tlsInfo.State.VerifiedChains)
		log.Printf("\n tlsInfo.State.PeerCertificates. %+v", tlsInfo.State.PeerCertificates)
		if len(tlsInfo.State.VerifiedChains) > 0 && len(tlsInfo.State.VerifiedChains[0]) > 0 {
			leaf = tlsInfo.State.VerifiedChains[0][0]
		} else if len(tlsInfo.State.PeerCertificates) > 0 {
			leaf = tlsInfo.State.PeerCertificates[0]
		}

		if leaf == nil {
			return nil, status.Error(codes.Unauthenticated, "no client certificate provided")
		}

		// compute fingerprint
		spkiDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			slog.Warn("failed to marshal public key", slog.String("error", err.Error()))
			return nil, status.Error(codes.Unauthenticated, "invalid client certificate")
		}
		sum := sha256.Sum256(spkiDER)
		fp := hex.EncodeToString(sum[:])

		account, err := db.GetAccountByClientPubkeyFP(ctx, fp)
		if err != nil {
			if err == sql.ErrNoRows {
				slog.Warn("unknown client public key fingerprint", slog.String("fp", fp))
				return nil, status.Error(codes.Unauthenticated, "unknown client certificate")
			}
			slog.Warn("error looking up account by fingerprint", slog.String("error", err.Error()))
			return nil, status.Error(codes.Unauthenticated, "unknown client certificate")
		}
		if !account.Active {
			return nil, status.Error(codes.Unavailable, "Your key is inactive")
		}

		signerInfo := signer.SignerInfo{
			AccountId:  account.Id,
			Derivation: uint32(account.Derivation),
		}
		// Add user info to context
		ctx = context.WithValue(ctx, signerInfoKey, signerInfo)

		return handler(ctx, req)
	}
}

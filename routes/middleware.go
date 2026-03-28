package routes

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"strconv"

	"nutmix_remote_signer/database"
	sig "nutmix_remote_signer/gen"
	"nutmix_remote_signer/signer"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const signatorySchemaVersion = "x-signatory-schema-version"
const signerInfoKey = "signerInfo"

func SchemaVersion() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
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

func AuthMiddleware(db database.SqliteDB) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		p, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "no peer info")
		}

		tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "no TLS info")
		}

		var leaf *x509.Certificate
		if len(tlsInfo.State.PeerCertificates) > 0 {
			leaf = tlsInfo.State.PeerCertificates[0]
		}
		if leaf == nil {
			return nil, status.Error(codes.Unauthenticated, "no client certificate provided")
		}

		spkiDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid client certificate")
		}
		sum := sha256.Sum256(spkiDER)
		fp := hex.EncodeToString(sum[:])

		account, err := db.GetAccountByClientPubkeyFP(ctx, fp)
		if err != nil {
			if err == sql.ErrNoRows {
				fallback, fallbackErr := db.GetAccountByID(database.DefaultAccountID)
				if fallbackErr == nil && fallback.ClientPubkeyFP == "" {
					account = *fallback
				} else {
					return nil, status.Error(codes.Unauthenticated, "unknown client certificate")
				}
			} else {
				return nil, status.Error(codes.Unauthenticated, "unknown client certificate")
			}
		}
		if !account.Active {
			return nil, status.Error(codes.Unavailable, "Your key is inactive")
		}

		signerInfo := signer.SignerInfo{AccountID: account.Id, Derivation: account.Derivation}
		ctx = context.WithValue(ctx, signerInfoKey, signerInfo)
		return handler(ctx, req)
	}
}

package routes

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"nutmix_remote_signer/database"
	"nutmix_remote_signer/signer"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestAuthMiddlewareInjectsSignerInfo(t *testing.T) {
	sqlite := setupRouteTestDB(t)
	ctx := context.Background()
	fp, tlsInfo := testTLSInfo(t)

	tx, err := sqlite.Db.Begin()
	if err != nil {
		t.Fatalf("sqlite.Db.Begin(): %v", err)
	}
	account := database.Account{Active: true, Id: "account-a", Name: "a", Derivation: 42, ClientPubkeyFP: fp, CreatedAt: 1}
	if err := sqlite.CreateAccount(tx, &account); err != nil {
		t.Fatalf("sqlite.CreateAccount(tx, &account): %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("tx.Commit(): %v", err)
	}

	ctx = peer.NewContext(ctx, &peer.Peer{AuthInfo: tlsInfo})
	called := false
	_, err = AuthMiddleware(sqlite)(ctx, nil, &grpc.UnaryServerInfo{}, func(handlerCtx context.Context, req interface{}) (interface{}, error) {
		called = true
		signerInfo, ok := handlerCtx.Value(signerInfoKey).(signer.SignerInfo)
		if !ok {
			t.Fatalf("signer info missing from context")
		}
		if signerInfo.AccountID != account.Id {
			t.Fatalf("signerInfo.AccountID = %q, want %q", signerInfo.AccountID, account.Id)
		}
		if signerInfo.Derivation != account.Derivation {
			t.Fatalf("signerInfo.Derivation = %d, want %d", signerInfo.Derivation, account.Derivation)
		}
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("AuthMiddleware(...): %v", err)
	}
	if !called {
		t.Fatalf("handler was not called")
	}
}

func TestAuthMiddlewareRejectsInactiveAccount(t *testing.T) {
	sqlite := setupRouteTestDB(t)
	ctx := context.Background()
	fp, tlsInfo := testTLSInfo(t)

	tx, err := sqlite.Db.Begin()
	if err != nil {
		t.Fatalf("sqlite.Db.Begin(): %v", err)
	}
	account := database.Account{Active: false, Id: "inactive", Name: "inactive", Derivation: 7, ClientPubkeyFP: fp, CreatedAt: 1}
	if err := sqlite.CreateAccount(tx, &account); err != nil {
		t.Fatalf("sqlite.CreateAccount(tx, &account): %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("tx.Commit(): %v", err)
	}

	ctx = peer.NewContext(ctx, &peer.Peer{AuthInfo: tlsInfo})
	_, err = AuthMiddleware(sqlite)(ctx, nil, &grpc.UnaryServerInfo{}, func(handlerCtx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if err == nil {
		t.Fatalf("expected auth error")
	}
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("status.Code(err) = %v, want %v", status.Code(err), codes.Unavailable)
	}
}

func TestAuthMiddlewareFallsBackToDefaultAccount(t *testing.T) {
	sqlite := setupRouteTestDB(t)
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: mustTLSInfo(t)})

	called := false
	_, err := AuthMiddleware(sqlite)(ctx, nil, &grpc.UnaryServerInfo{}, func(handlerCtx context.Context, req interface{}) (interface{}, error) {
		called = true
		signerInfo, ok := handlerCtx.Value(signerInfoKey).(signer.SignerInfo)
		if !ok {
			t.Fatalf("signer info missing from context")
		}
		if signerInfo.AccountID != database.DefaultAccountID {
			t.Fatalf("signerInfo.AccountID = %q, want %q", signerInfo.AccountID, database.DefaultAccountID)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("AuthMiddleware fallback returned error: %v", err)
	}
	if !called {
		t.Fatalf("handler was not called")
	}
}

func setupRouteTestDB(t *testing.T) database.SqliteDB {
	t.Helper()
	sqlite, err := database.DatabaseSetup(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("database.DatabaseSetup(...): %v", err)
	}
	t.Cleanup(func() { _ = sqlite.Db.Close() })
	return sqlite
}

func mustTLSInfo(t *testing.T) credentials.TLSInfo {
	t.Helper()
	_, tlsInfo := testTLSInfo(t)
	return tlsInfo
}

func testTLSInfo(t *testing.T) (string, credentials.TLSInfo) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(...): %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(...): %v", err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(...): %v", err)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey(...): %v", err)
	}
	sum := sha256.Sum256(spkiDER)
	return hex.EncodeToString(sum[:]), credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}
}

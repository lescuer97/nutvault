package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	accountmanager "nutmix_remote_signer/account_manager"
	"nutmix_remote_signer/database"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/go-chi/chi/v5"
)

func TestLoginHandlers(t *testing.T) {
	serverData, _, _, _ := setupWebTestServerData(t)
	resp := httptest.NewRecorder()
	LoginGetHandler(serverData)(resp, httptest.NewRequest(http.MethodGet, "/login", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("LoginGetHandler status = %d, want %d", resp.Code, http.StatusOK)
	}
	if !strings.Contains(resp.Body.String(), "Connect with Nostr") {
		t.Fatalf("expected login page content")
	}

	resp = httptest.NewRecorder()
	badReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("not-json"))
	LoginPostHandler(serverData, []byte("secret"))(resp, badReq)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("LoginPostHandler status = %d, want %d", resp.Code, http.StatusBadRequest)
	}
}

func TestDashboardHandler(t *testing.T) {
	serverData, _, account, _ := setupWebTestServerData(t)
	req := withAudienceContext(httptest.NewRequest(http.MethodGet, "/", nil), account.Npub)
	resp := httptest.NewRecorder()
	DashboardHandler(serverData)(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("DashboardHandler status = %d, want %d", resp.Code, http.StatusOK)
	}
	if !strings.Contains(resp.Body.String(), account.Id) {
		t.Fatalf("dashboard response should contain account id")
	}
}

func TestCreateKeyHandler(t *testing.T) {
	serverData, _, _, ownerPriv := setupWebTestServerData(t)
	req := withAudienceContext(httptest.NewRequest(http.MethodPost, "/createkey", nil), ownerPriv.PubKey())
	resp := httptest.NewRecorder()
	CreateKeyHandler(serverData)(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("CreateKeyHandler status = %d, want %d", resp.Code, http.StatusOK)
	}
	if !strings.Contains(resp.Body.String(), "Details") {
		t.Fatalf("expected account card response")
	}
}

func TestSignerDashboardOwnership(t *testing.T) {
	serverData, _, account, _ := setupWebTestServerData(t)
	otherPriv, _ := btcec.PrivKeyFromBytes([]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9})
	req := withAccountRequestContext(httptest.NewRequest(http.MethodGet, "/signer/"+account.Id, nil), account.Id, otherPriv.PubKey())
	resp := httptest.NewRecorder()
	SignerDashboard(serverData)(resp, req)
	if resp.Code == http.StatusOK {
		t.Fatalf("expected ownership failure")
	}
}

func TestKeysetsHandler(t *testing.T) {
	serverData, sqlite, account, _ := setupWebTestServerData(t)
	tx, err := sqlite.Db.Begin()
	if err != nil {
		t.Fatalf("db.Begin(): %v", err)
	}
	seed := database.Seed{Active: true, Version: 1, Id: "seed-web", Unit: "SAT", AccountID: account.Id, Amounts: []uint64{1}, CreatedAt: 1, DerivationPath: "0/0/0"}
	if err := sqlite.SaveNewSeed(tx, seed); err != nil {
		t.Fatalf("SaveNewSeed(...): %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("tx.Commit(): %v", err)
	}

	req := withAccountRequestContext(httptest.NewRequest(http.MethodGet, "/signer/"+account.Id+"/keysets", nil), account.Id, account.Npub)
	resp := httptest.NewRecorder()
	KeysetsListHandler(serverData)(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("KeysetsListHandler status = %d, want %d", resp.Code, http.StatusOK)
	}
	if !strings.Contains(resp.Body.String(), "seed-web") {
		t.Fatalf("expected keyset id in response")
	}
}

func TestToggleAccountActiveHandler(t *testing.T) {
	serverData, _, account, _ := setupWebTestServerData(t)
	req := withAccountRequestContext(httptest.NewRequest(http.MethodPost, "/accounts/"+account.Id+"/toggle-active", nil), account.Id, account.Npub)
	resp := httptest.NewRecorder()
	ToggleAccountActiveHandler(serverData)(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("ToggleAccountActiveHandler status = %d, want %d", resp.Code, http.StatusOK)
	}
	active, err := serverData.manager.GetKeyActive(context.Background(), account.Id)
	if err != nil {
		t.Fatalf("GetKeyActive(...): %v", err)
	}
	if active {
		t.Fatalf("expected account to be toggled inactive")
	}
}

func TestCertHandler(t *testing.T) {
	serverData, account, _ := setupWebCertServerData(t)
	req := withAccountAndWhichRequestContext(httptest.NewRequest(http.MethodGet, "/cert/"+account.Id+"/ca", nil), account.Id, "ca", account.Npub)
	resp := httptest.NewRecorder()
	CertHandler(serverData)(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("CertHandler status = %d, want %d", resp.Code, http.StatusOK)
	}
	if !strings.Contains(resp.Body.String(), "CERTIFICATE") {
		t.Fatalf("expected certificate content in response")
	}

	otherPriv, _ := btcec.PrivKeyFromBytes([]byte{8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8})
	req = withAccountAndWhichRequestContext(httptest.NewRequest(http.MethodGet, "/cert/"+account.Id+"/cert", nil), account.Id, "cert", otherPriv.PubKey())
	resp = httptest.NewRecorder()
	CertHandler(serverData)(resp, req)
	if resp.Code == http.StatusOK {
		t.Fatalf("expected foreign access to fail")
	}
}

func TestCertDownloadHandler(t *testing.T) {
	serverData, account, _ := setupWebCertServerData(t)
	req := withAccountAndWhichRequestContext(httptest.NewRequest(http.MethodGet, "/cert/"+account.Id+"/key/download", nil), account.Id, "key", account.Npub)
	resp := httptest.NewRecorder()
	CertDownloadHandler(serverData)(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("CertDownloadHandler status = %d, want %d", resp.Code, http.StatusOK)
	}
	if !strings.Contains(resp.Header().Get("Content-Disposition"), ".pem") {
		t.Fatalf("expected pem download header")
	}
}

func TestHideCertHandler(t *testing.T) {
	serverData, account, _ := setupWebCertServerData(t)
	req := withAccountAndWhichRequestContext(httptest.NewRequest(http.MethodGet, "/cert/"+account.Id+"/cert/hide", nil), account.Id, "cert", account.Npub)
	resp := httptest.NewRecorder()
	HideCertHandler(serverData)(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("HideCertHandler status = %d, want %d", resp.Code, http.StatusOK)
	}
	if !strings.Contains(resp.Body.String(), "****") {
		t.Fatalf("expected closed cert row response")
	}
}

func setupWebTestServerData(t *testing.T) (*ServerData, database.SqliteDB, *database.Account, *btcec.PrivateKey) {
	t.Helper()
	sqlite, err := database.DatabaseSetup(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("database.DatabaseSetup(...): %v", err)
	}
	t.Cleanup(func() { _ = sqlite.Db.Close() })
	manager := accountmanager.NewManager(&sqlite, nil)
	priv, _ := btcec.PrivKeyFromBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})
	account, err := manager.CreateAccount(context.Background(), priv.PubKey(), "fingerprint")
	if err != nil {
		t.Fatalf("manager.CreateAccount(...): %v", err)
	}
	serverData, err := NewServerData(&manager)
	if err != nil {
		t.Fatalf("NewServerData(...): %v", err)
	}
	serverData.manager = &manager
	return serverData, sqlite, account, priv
}

func setupWebCertServerData(t *testing.T) (*ServerData, *database.Account, *btcec.PrivateKey) {
	t.Helper()
	sqlite, err := database.DatabaseSetup(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("database.DatabaseSetup(...): %v", err)
	}
	t.Cleanup(func() { _ = sqlite.Db.Close() })
	manager := accountmanager.NewManager(&sqlite, nil)
	caCertPEM, caKeyPEM := testCAArtifacts(t)
	manager.ConfigureCertificates(caCertPEM, caKeyPEM, t.TempDir())
	priv, _ := btcec.PrivKeyFromBytes([]byte{6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6})
	account, err := manager.CreateAccount(context.Background(), priv.PubKey(), "")
	if err != nil {
		t.Fatalf("manager.CreateAccount(...): %v", err)
	}
	serverData, err := NewServerData(&manager)
	if err != nil {
		t.Fatalf("NewServerData(...): %v", err)
	}
	return serverData, account, priv
}

func withAccountRequestContext(req *http.Request, accountID string, pubkey *btcec.PublicKey) *http.Request {
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("id", accountID)
	return withAudienceContext(req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx)), pubkey)
}

func withAccountAndWhichRequestContext(req *http.Request, accountID string, which string, pubkey *btcec.PublicKey) *http.Request {
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("id", accountID)
	chiCtx.URLParams.Add("which", which)
	return withAudienceContext(req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx)), pubkey)
}

func hexPub(pubkey *btcec.PublicKey) string {
	if pubkey == nil {
		return ""
	}
	return hex.EncodeToString(pubkey.SerializeCompressed())
}

func testCAArtifacts(t *testing.T) ([]byte, []byte) {
	t.Helper()
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(...): %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("rand.Int(...): %v", err)
	}
	caTmpl := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Web Test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(2, 0, 0), IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTmpl, &caTmpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(...): %v", err)
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caKeyBytes, err := x509.MarshalECPrivateKey(caPriv)
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey(...): %v", err)
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyBytes})
	return caCertPEM, caKeyPEM
}

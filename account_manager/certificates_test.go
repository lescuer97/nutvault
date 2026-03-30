package accountmanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nutmix_remote_signer/database"

	"github.com/btcsuite/btcd/btcec/v2"
)

func TestProvisionAccountCertificates(t *testing.T) {
	manager, _, dir := setupCertificateManager(t)
	fingerprint, err := manager.ProvisionAccountCertificates("account-a")
	if err != nil {
		t.Fatalf("manager.ProvisionAccountCertificates(...): %v", err)
	}
	if fingerprint == "" {
		t.Fatalf("fingerprint should not be empty")
	}
	if _, err := os.Stat(filepath.Join(dir, "account-a-cert.pem")); err != nil {
		t.Fatalf("cert file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "account-a-key.pem")); err != nil {
		t.Fatalf("key file missing: %v", err)
	}
	certPEM, err := manager.GetCertificate("account-a")
	if err != nil {
		t.Fatalf("manager.GetCertificate(...): %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("invalid cert PEM returned")
	}
}

func TestGetCertificatePaths(t *testing.T) {
	manager, _, _ := setupCertificateManager(t)
	if _, err := safeJoinFile(manager.TlsConfigDir(), "../escape.pem"); err == nil {
		t.Fatalf("expected safeJoinFile to reject traversal")
	}
	if _, err := safeJoinFile(manager.TlsConfigDir(), "account-cert.pem"); err != nil {
		t.Fatalf("safeJoinFile(valid): %v", err)
	}
}

func TestClientPubkeyFingerprint(t *testing.T) {
	manager, _, _ := setupCertificateManager(t)
	fingerprint, err := manager.ProvisionAccountCertificates("account-b")
	if err != nil {
		t.Fatalf("manager.ProvisionAccountCertificates(...): %v", err)
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		t.Fatalf("fingerprint is not valid hex: %v", err)
	}
	if len(fingerprint) != 64 {
		t.Fatalf("fingerprint length = %d, want 64", len(fingerprint))
	}
}

func TestCreateAccountProvisionsCertificatesWhenConfigured(t *testing.T) {
	manager, sqlite, dir := setupCertificateManager(t)
	defer func() { _ = sqlite.Db.Close() }()
	priv, _ := btcec.PrivKeyFromBytes([]byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7})
	account, err := manager.CreateAccount(t.Context(), priv.PubKey(), "")
	if err != nil {
		t.Fatalf("manager.CreateAccount(...): %v", err)
	}
	if account.ClientPubkeyFP == "" {
		t.Fatalf("expected generated client fingerprint")
	}
	if _, err := os.Stat(filepath.Join(dir, account.Id+"-cert.pem")); err != nil {
		t.Fatalf("generated cert missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, account.Id+"-key.pem")); err != nil {
		t.Fatalf("generated key missing: %v", err)
	}
}

func setupCertificateManager(t *testing.T) (Manager, database.SqliteDB, string) {
	t.Helper()
	sqlite, err := database.DatabaseSetup(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("database.DatabaseSetup(...): %v", err)
	}
	dir := t.TempDir()
	caCertPEM, caKeyPEM := testCA(t)
	manager := NewManager(&sqlite, nil)
	manager.ConfigureCertificates(caCertPEM, caKeyPEM, dir)
	return manager, sqlite, dir
}

func testCA(t *testing.T) ([]byte, []byte) {
	t.Helper()
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(...): %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("rand.Int(...): %v", err)
	}
	caTmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
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

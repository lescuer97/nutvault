package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateAndSaveTLSKeyFromCA(t *testing.T) {
	// Create a temporary dir for config
	dir := t.TempDir()
	name := "testclient"

	// Generate CA key (ECDSA P-256)
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	// CA certificate template
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, &caTmpl, &caTmpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caKeyBytes, err := x509.MarshalECPrivateKey(caPriv)
	if err != nil {
		t.Fatalf("failed to marshal CA private key: %v", err)
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyBytes})

	// Call the function under test
	pubPEM, err := CreateAndSaveTLSKeyFromCA(caCertPEM, caKeyPEM, name, dir)
	if err != nil {
		t.Fatalf("CreateAndSaveTLSKeyFromCA failed: %v", err)
	}

	// Check files exist
	certPath := filepath.Join(dir, name+"-cert.pem")
	keyPath := filepath.Join(dir, name+"-key.pem")

	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("certificate file not found: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key file not found: %v", err)
	}

	// Read and parse cert
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read cert file: %v", err)
	}
	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" {
		t.Fatalf("failed to decode saved certificate PEM")
	}
	if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
		t.Fatalf("saved certificate parse error: %v", err)
	}

	// Read and parse key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}
	kblk, _ := pem.Decode(keyPEM)
	if kblk == nil {
		t.Fatalf("failed to decode saved key PEM")
	}
	if kblk.Type != "EC PRIVATE KEY" && kblk.Type != "PRIVATE KEY" && kblk.Type != "RSA PRIVATE KEY" {
		t.Fatalf("unexpected key PEM type: %s", kblk.Type)
	}
	// Try to parse EC private key
	if _, err := x509.ParseECPrivateKey(kblk.Bytes); err != nil {
		// If that fails, try PKCS8
		if _, err2 := x509.ParsePKCS8PrivateKey(kblk.Bytes); err2 != nil {
			t.Fatalf("failed to parse saved private key: %v / %v", err, err2)
		}
	}

	// Parse returned public key
	pblk, _ := pem.Decode(pubPEM)
	if pblk == nil || pblk.Type != "PUBLIC KEY" {
		t.Fatalf("failed to decode returned public key PEM")
	}
	if _, err := x509.ParsePKIXPublicKey(pblk.Bytes); err != nil {
		t.Fatalf("failed to parse returned public key: %v", err)
	}
}

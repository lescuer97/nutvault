package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func CreateAndSaveTLSKeyFromCA(caCertPEM, caKeyPEM []byte, name, configDir string) ([]byte, error) {
	if name == "" {
		return nil, fmt.Errorf("name must not be empty")
	}

	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParseCertificate(ca). %w", err)
	}

	caKey, err := parsePrivateKeyPEM(caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parsePrivateKeyPEM(caKey). %w", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa.GenerateKey: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("rand.Int: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("x509.CreateCertificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("x509.MarshalECPrivateKey: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	if err := SaveTLSKey(configDir, name, certPEM, keyPEM); err != nil {
		return nil, err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("x509.MarshalPKIXPublicKey: %w", err)
	}
	return pubBytes, nil
}

func SaveTLSKey(configDir, name string, certPEM, keyPEM []byte) error {
	if name == "" {
		return fmt.Errorf("name must not be empty")
	}

	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("os.MkdirAll(%s): %w", configDir, err)
	}

	certPath := filepath.Join(configDir, fmt.Sprintf("%s-cert.pem", name))
	keyPath := filepath.Join(configDir, fmt.Sprintf("%s-key.pem", name))

	if _, err := os.Stat(certPath); err == nil {
		return fmt.Errorf("certificate file already exists: %s", certPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat certPath: %w", err)
	}

	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("key file already exists: %s", keyPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat keyPath: %w", err)
	}

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		_ = os.Remove(certPath)
		return fmt.Errorf("write key: %w", err)
	}

	return nil
}

func parsePrivateKeyPEM(pemBytes []byte) (interface{}, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	switch blk.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		return k, nil
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		return k, nil
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		switch key := k.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("unsupported PKCS#8 key type: %T", key)
		}
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", blk.Type)
	}
}

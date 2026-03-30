package accountmanager

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sharedutils "nutmix_remote_signer/utils"
)

func (m *Manager) ConfigureCertificates(caCertPEM, caKeyPEM []byte, tlsDir string) {
	m.caCertPEM = append([]byte(nil), caCertPEM...)
	m.caKeyPEM = append([]byte(nil), caKeyPEM...)
	m.tlsConfigDir = tlsDir
}

func (m *Manager) ProvisionAccountCertificates(accountID string) (string, error) {
	if accountID == "" {
		return "", fmt.Errorf("account id is required")
	}
	if len(m.caCertPEM) == 0 || len(m.caKeyPEM) == 0 {
		return "", fmt.Errorf("ca certificate material is not configured")
	}
	if m.tlsConfigDir == "" {
		return "", fmt.Errorf("tls config dir is not configured")
	}

	pubKeyDER, err := sharedutils.CreateAndSaveTLSKeyFromCA(m.caCertPEM, m.caKeyPEM, accountID, m.tlsConfigDir)
	if err != nil {
		return "", fmt.Errorf("utils.CreateAndSaveTLSKeyFromCA(...): %w", err)
	}
	sha := sha256.Sum256(pubKeyDER)
	return hex.EncodeToString(sha[:]), nil
}

func (m *Manager) GetCertificate(name string) ([]byte, error) {
	path, err := safeJoinFile(m.tlsConfigDir, name+"-cert.pem")
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("os.ReadFile(%s): %w", path, err)
	}
	return data, nil
}

func (m *Manager) GetTLSKey(name string) ([]byte, error) {
	path, err := safeJoinFile(m.tlsConfigDir, name+"-key.pem")
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("os.ReadFile(%s): %w", path, err)
	}
	return data, nil
}

func (m *Manager) GetCACertPEM() []byte {
	return append([]byte(nil), m.caCertPEM...)
}

func (m *Manager) TlsConfigDir() string {
	return m.tlsConfigDir
}

func safeJoinFile(baseDir string, name string) (string, error) {
	if baseDir == "" {
		return "", fmt.Errorf("base directory is empty")
	}
	if name == "" {
		return "", fmt.Errorf("file name is empty")
	}
	if filepath.Base(name) != name {
		return "", fmt.Errorf("invalid file name: %s", name)
	}
	if strings.Contains(name, "..") {
		return "", fmt.Errorf("invalid file name: %s", name)
	}
	return filepath.Join(baseDir, name), nil
}

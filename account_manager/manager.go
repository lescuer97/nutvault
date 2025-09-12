package accountmanager

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"nutmix_remote_signer/database"
	"nutmix_remote_signer/utils"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Manager struct {
	db *database.SqliteDB
	caCertPEM   []byte
	caKeyPEM    []byte
	tlsConfigDir string
}

func NewManager(db *database.SqliteDB, caCertPEM, caKeyPEM []byte, tlsDir string) Manager {
	m := Manager{db: db}
	m.caCertPEM = caCertPEM
	m.caKeyPEM = caKeyPEM
	m.tlsConfigDir = tlsDir
	return m
}

// MakeSignerKey is a placeholder for future signer logic.
func (m *Manager) MakeSignerKey(pubkey *btcec.PublicKey) error {
	return nil
}

// CreateAccount creates and persists a new account using the provided pubkey.
// npub is stored as the compressed bytes of the public key (SerializeCompressed).
// Derivation is assigned to the next available integer (MAX(derivation)+1).
// Additionally, if CA credentials are configured on the manager, a TLS key/cert
// is generated, saved to disk (name = account id), and the generated public key
// PEM is used to compute ClientPubkeyFP which is stored on the account before saving.
// If TLS generation fails, CreateAccount will return an error and not persist the account.
func (m *Manager) CreateAccount(ctx context.Context, pubkey *btcec.PublicKey) (*database.Account, error) {
	if m == nil || m.db == nil || m.db.Db == nil {
		return nil, fmt.Errorf("manager database is not initialized")
	}

	// Compute npub from compressed pubkey bytes
	npub := pubkey.SerializeCompressed()

	// Generate a random ID (32 bytes hex)
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("rand.Read: %w", err)
	}
	id := hex.EncodeToString(idBytes)

	// Pick next derivation index
	derivation := makeDerivation(pubkey, idBytes)
	derivationInt := binary.LittleEndian.Uint32(derivation)

	acc := database.Account{
		Active:     true,
		Npub:       npub,
		Id:         id,
		Derivation: derivationInt,
		CreatedAt:  time.Now().Unix(),
		Signature:  nil, // placeholder not parsed back
	}

	// If CA credentials are configured, create TLS key/cert and save to disk.
	if len(m.caCertPEM) > 0 && len(m.caKeyPEM) > 0 {
		if m.tlsConfigDir == "" {
			// set default if not set
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("os.UserHomeDir: %w", err)
			}
			m.tlsConfigDir = filepath.Join(home, ".config", "nutvault", "certificates")
		}

		pubPEM, err := utils.CreateAndSaveTLSKeyFromCA(m.caCertPEM, m.caKeyPEM, id, m.tlsConfigDir)
		if err != nil {
			// Fail creation if TLS key generation fails
			return nil, fmt.Errorf("CreateAndSaveTLSKeyFromCA: %w", err)
		}
		// Compute and set client pubkey fingerprint (sha256 of public key PEM)
		sha := sha256.Sum256(pubPEM)
		acc.ClientPubkeyFP = hex.EncodeToString(sha[:])
	}

	err := m.db.CreateAccount(&acc)
	if err != nil {
		return nil, fmt.Errorf("m.db.CreateAccount(&acc). %w", err)

	}
	return &acc, nil
}

func (m *Manager) GetAccountsFromNpub(pubkey *secp256k1.PublicKey) ([]database.Account, error) {
	accounts, err := m.db.GetAccountsByNpub(pubkey.SerializeCompressed())
	if err != nil {
		return nil, err
	}
	return accounts, nil
}

func makeDerivation(pubkey *secp256k1.PublicKey, id []byte) []byte {
	bytes := []byte{}

	bytes = append(bytes, pubkey.SerializeCompressed()...)
	bytes = append(bytes, id...)

	sha256Bytes := sha256.Sum256(bytes)
	return sha256Bytes[:]
}

// GetCertificate reads a certificate file from the manager's tlsConfigDir.
// It attempts to read <name>.pem first, and if not present falls back to <name>-cert.pem.
// If tlsConfigDir is empty it defaults to $HOME/.config/nutvault/certificates.
func (m *Manager) GetCertificate(name string) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("manager is nil")
	}
	dir := m.tlsConfigDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("os.UserHomeDir: %w", err)
		}
		dir = filepath.Join(home, ".config", "nutvault", "certificates")
	}

	// Try name.pem
	p1 := filepath.Join(dir, name+".pem")
	data, err := os.ReadFile(p1)
	if err == nil {
		return data, nil
	}

	// Fallback to name-cert.pem for compatibility
	p2 := filepath.Join(dir, name+"-cert.pem")
	data2, err2 := os.ReadFile(p2)
	if err2 == nil {
		return data2, nil
	}

	return nil, fmt.Errorf("could not read certificate: tried %s (%v) and %s (%v)", p1, err, p2, err2)
}

package accountmanager

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"nutmix_remote_signer/database"
	"nutmix_remote_signer/signer"
	"nutmix_remote_signer/utils"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Manager struct {
	db           *database.SqliteDB
	caCertPEM    []byte
	caKeyPEM     []byte
	tlsConfigDir string
	signer       *signer.MultiAccountSigner
}

var ErrAuthorizedNpubAlreadyExists = errors.New("Authorized npub already exists")

// NewManager returns a Manager and ensures the provided tlsDir exists.
// If tlsDir is empty it defaults to $HOME/.config/nutvault/certificates.
// The function attempts to create the directory with mode 0700 if it doesn't exist.
func NewManager(db *database.SqliteDB, caCertPEM, caKeyPEM []byte, tlsDir string, signer *signer.MultiAccountSigner) Manager {
	m := Manager{db: db, signer: signer}
	m.caCertPEM = caCertPEM
	m.caKeyPEM = caKeyPEM

	// Determine TLS config directory (use default if not provided)
	dir := tlsDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			// fallback to current directory if UserHomeDir is not available
			log.Printf("warning: could not determine user home directory: %v", err)
			dir = filepath.Join(".", ".config", "nutvault", "certificates")
		} else {
			dir = filepath.Join(home, ".config", "nutvault", "certificates")
		}
	}

	// Ensure the directory exists
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Printf("warning: failed to create tls config dir %s: %v", dir, err)
	}

	m.tlsConfigDir = dir
	return m
}

// CreateKey creates and persists a new account using the provided pubkey.
// npub is stored as the compressed bytes of the public key (SerializeCompressed).
// Derivation is assigned to the next available integer (MAX(derivation)+1).
// Additionally, if CA credentials are configured on the manager, a TLS key/cert
// is generated, saved to disk (name = account id), and the generated public key
// PEM is used to compute ClientPubkeyFP which is stored on the account before saving.
// If TLS generation fails, CreateKey will return an error and not persist the account.
func (m *Manager) CreateKey(ctx context.Context, pubkey *btcec.PublicKey) (*database.IndividualKey, error) {
	if m.db == nil {
		log.Panicf("database should not be nil")
	}
	if m.db.Db == nil {
		log.Panicf("m.db.Db should not be nil")
	}
	if pubkey == nil {
		log.Panic("pubkey should not have been nil at this point")
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

	acc := database.IndividualKey{
		Active:     true,
		Npub:       npub,
		Id:         id,
		Derivation: derivationInt,
		CreatedAt:  time.Now().Unix(),
	}

	// If CA credentials are configured, create TLS key/cert and save to disk.
	// ensure tlsConfigDir is set (should have been set in NewManager)
	if m.tlsConfigDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("os.UserHomeDir: %w", err)
		}
		m.tlsConfigDir = filepath.Join(home, ".config", "nutvault", "certificates")
		// attempt to create if missing
		if err := os.MkdirAll(m.tlsConfigDir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create tls config dir: %w", err)
		}
	}

	pubPEM, err := utils.CreateAndSaveTLSKeyFromCA(m.caCertPEM, m.caKeyPEM, id, m.tlsConfigDir)
	if err != nil {
		// Fail creation if TLS key generation fails
		return nil, fmt.Errorf("CreateAndSaveTLSKeyFromCA: %w", err)
	}
	sha := sha256.Sum256(pubPEM)
	acc.ClientPubkeyFP = hex.EncodeToString(sha[:])

	slog.Debug("Adding new account in database.", slog.String("accountId", acc.Id))
	err = m.db.CreateAccount(&acc)
	if err != nil {
		return nil, fmt.Errorf("m.db.CreateAccount(&acc). %w", err)
	}

	slog.Debug("Generating new keys in the signer", slog.String("accountId", acc.Id))
	err = m.signer.AddKeysToSignerFromAccount(acc.Id, acc.Derivation)
	if err != nil {
		return nil, fmt.Errorf("m.signer.GenerateSigningKeys(acc.Id, acc.Derivation). %w", err)
	}

	return &acc, nil
}

// UpdatKeyName updates the name of an existing account. Returns an error
// if the manager or database is not properly initialized.
func (m *Manager) UpdatKeyName(ctx context.Context, id string, name string) error {
	if m.db == nil {
		log.Panicf("database should not be nil")
	}
	if m.db.Db == nil {
		log.Panicf("m.db.Db should not be nil")
	}
	return m.db.UpdateAccountName(id, name)
}

func (m *Manager) GetKeysFromNpub(pubkey *secp256k1.PublicKey) ([]database.IndividualKey, error) {
	if m.db == nil {
		log.Panicf("database should not be nil")
	}
	if m.db.Db == nil {
		log.Panicf("m.db.Db should not be nil")
	}
	if pubkey == nil {
		log.Panicf("pubkey should have never been null at this point")
	}

	accounts, err := m.db.GetAccountsByNpub(pubkey.SerializeCompressed())
	if err != nil {
		return nil, err
	}
	return accounts, nil
}
func (m *Manager) GetKeyById(id string) (*database.IndividualKey, error) {
	account, err := m.db.GetKeyById(id)
	if err != nil {
		return nil, err
	}
	return account, nil
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

// GetCACertPEM returns the CA certificate PEM configured for the manager (may be empty)
func (m *Manager) GetCACertPEM() []byte {
	if m == nil {
		return nil
	}
	return m.caCertPEM
}

// TlsConfigDir returns the configured TLS certificates directory
func (m *Manager) TlsConfigDir() string {
	if m == nil {
		return ""
	}
	return m.tlsConfigDir
}

// GetKeysetsForAccount retrieves all keysets (seeds) for a given account ID with proper transaction handling
func (m *Manager) GetKeysetsForAccount(ctx context.Context, accountId string) ([]database.Seed, error) {
	if m.db == nil {
		log.Panicf("database should not be nil")
	}
	if m.db.Db == nil {
		log.Panicf("m.db.Db should not be nil")
	}
	tx, err := m.db.Db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	seeds, err := m.db.GetSeedsByAccountId(tx, accountId)
	if err != nil {
		return nil, fmt.Errorf("GetSeedsByAccountId: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return seeds, nil
}

// SetKeyActive sets the active status for all seeds belonging to an account
func (m *Manager) SetKeyActive(ctx context.Context, accountID string, active bool) error {
	if m.db == nil {
		log.Panicf("database should not be nil")
	}
	if m.db.Db == nil {
		log.Panicf("m.db.Db should not be nil")
	}

	// Update all seeds for this account
	if err := m.db.UpdateKeyActive(accountID, active); err != nil {
		return fmt.Errorf("UpdateSeedsActiveStatus: %w", err)
	}

	return nil
}

// GetKeyActive returns the active status for an account by checking if any of its seeds are active
func (m *Manager) GetKeyActive(ctx context.Context, accountID string) (bool, error) {
	if m.db == nil {
		log.Panicf("database should not be nil")
	}
	if m.db.Db == nil {
		log.Panicf("m.db.Db should not be nil")
	}

	// Get all seeds for this account and check if any are active
	account, err := m.db.GetKeyById(accountID)
	if err != nil {
		return false, fmt.Errorf("GetSeedsByAccountId: %w", err)
	}

	// Check if any seed is active

	return account.Active, nil
}

func (m *Manager) GetAllAuthNpubs() ([]database.AuthorizedNpub, error) {
	if m.db == nil {
		log.Panicf("database should not be nil")
	}
	if m.db.Db == nil {
		log.Panicf("m.db.Db should not be nil")
	}

	authNpubs, err := m.db.GetAllAuthorizedNpubs()
	if err != nil {
		return nil, fmt.Errorf("GetSeedsByAccountId: %w", err)
	}
	return authNpubs, nil
}

func (m *Manager) GetAuthNpubByNpub(ctx context.Context, npub *secp256k1.PublicKey) (database.AuthorizedNpub, error) {
	if m.db == nil {
		log.Panicf("database should not be nil")
	}
	if m.db.Db == nil {
		log.Panicf("m.db.Db should not be nil")
	}

	tx, err := m.db.Db.Begin()
	if err != nil {
		return database.AuthorizedNpub{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	// Get all seeds for this account and check if any are active
	authNpub, err := m.db.GetAuthorizedNpubByNpub(tx, npub)
	if err != nil {
		return database.AuthorizedNpub{}, fmt.Errorf("GetSeedsByAccountId: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return database.AuthorizedNpub{}, fmt.Errorf("commit: %w", err)
	}

	return *authNpub, nil
}
func (m *Manager) CreateAuthNpub(npubToAdd database.AuthorizedNpub) error {
	if m.db == nil {
		log.Panicf("database should not be nil")
	}
	if m.db.Db == nil {
		log.Panicf("m.db.Db should not be nil")
	}

	tx, err := m.db.Db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	authNpub, err := m.db.GetAuthorizedNpubByNpub(tx, npubToAdd.Npub)
	if err != nil {
		// INFO: we ignore this error because we want an npub that doesn't exists
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("GetSeedsByAccountId: %w", err)
		}
	}

	if authNpub != nil {
		return fmt.Errorf("user already exists. %w", ErrAuthorizedNpubAlreadyExists)
	}

	err = m.db.CreateAuthorizedNpub(tx, &npubToAdd)
	if err != nil {
		log.Printf("m.db.CreateAuthorizedNpub(tx, &authNpub). %+v", err)
		return fmt.Errorf("GetSeedsByAccountId: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}
func (m *Manager) ChangeAuthNpubActivation(ctx context.Context, npub *btcec.PublicKey, active bool) error {
	if m.db == nil {
		log.Panicf("database should not be nil")
	}
	if m.db.Db == nil {
		log.Panicf("m.db.Db should not be nil")
	}

	tx, err := m.db.Db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Get all seeds for this account and check if any are active
	npubToAdd, err := m.db.GetAuthorizedNpubByNpub(tx, npub)
	if err != nil {
		return fmt.Errorf("GetSeedsByAccountId: %w", err)
	}

	if npubToAdd.Npub == nil {
		panic("npub should have never been null after getting it from the database")
	}

	// Get all seeds for this account and check if any are active
	err = m.db.UpdateAuthorizedNpubActive(tx, npubToAdd.Npub, active)
	if err != nil {
		return fmt.Errorf("GetSeedsByAccountId: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

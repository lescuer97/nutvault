package accountmanager

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"nutmix_remote_signer/database"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Manager struct {
	db *database.SqliteDB
}

func NewManager(db *database.SqliteDB) Manager {
	return Manager{db: db}
}

// MakeSignerKey is a placeholder for future signer logic.
func (m *Manager) MakeSignerKey(pubkey *btcec.PublicKey) error {
	return nil
}

// CreateAccount creates and persists a new account using the provided pubkey.
// npub is stored as the compressed bytes of the public key (SerializeCompressed).
// Derivation is assigned to the next available integer (MAX(derivation)+1).
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

	// TODO: Generate the public key for connection from the mint
	acc := database.Account{
		Active:     true,
		Npub:       npub,
		Id:         id,
		Derivation: derivationInt,
		CreatedAt:  time.Now().Unix(),
		Signature:  nil, // placeholder not parsed back
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

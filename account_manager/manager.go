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
	"nutmix_remote_signer/signer"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Manager struct {
	db     *database.SqliteDB
	signer *signer.Signer
}

func NewManager(db *database.SqliteDB, signerInstance *signer.Signer) Manager {
	return Manager{db: db, signer: signerInstance}
}

func (m *Manager) CreateAccount(ctx context.Context, pubkey *btcec.PublicKey, clientPubkeyFP string) (*database.Account, error) {
	if m.db == nil || m.db.Db == nil {
		return nil, fmt.Errorf("database is not configured")
	}
	if pubkey == nil {
		return nil, fmt.Errorf("pubkey is required")
	}

	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("rand.Read(idBytes): %w", err)
	}
	account := database.Account{
		Active:         true,
		Npub:           pubkey,
		Id:             hex.EncodeToString(idBytes),
		Name:           "",
		ClientPubkeyFP: clientPubkeyFP,
		Derivation:     makeDerivation(pubkey, idBytes),
		CreatedAt:      time.Now().Unix(),
	}

	tx, err := m.db.Db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("m.db.Db.BeginTx(ctx, nil): %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if err := m.db.CreateAccount(tx, &account); err != nil {
		return nil, fmt.Errorf("m.db.CreateAccount(tx, &account): %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("tx.Commit(): %w", err)
	}

	if m.signer != nil {
		if err := m.signer.AddKeysToSignerFromAccount(account.Id); err != nil {
			return nil, fmt.Errorf("m.signer.AddKeysToSignerFromAccount(account.Id): %w", err)
		}
	}

	return &account, nil
}

func (m *Manager) GetKeyByID(id string) (*database.Account, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database is not configured")
	}
	return m.db.GetAccountByID(id)
}

func (m *Manager) GetKeysFromNpub(pubkey *secp256k1.PublicKey) ([]database.Account, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database is not configured")
	}
	accounts, err := m.db.GetAllAccounts()
	if err != nil {
		return nil, err
	}
	filtered := make([]database.Account, 0)
	for _, account := range accounts {
		if account.Npub != nil && pubkey != nil && account.Npub.IsEqual(pubkey) {
			filtered = append(filtered, account)
		}
	}
	return filtered, nil
}

func makeDerivation(pubkey *secp256k1.PublicKey, id []byte) uint32 {
	bytes := append([]byte{}, pubkey.SerializeCompressed()...)
	bytes = append(bytes, id...)
	sha256Bytes := sha256.Sum256(bytes)
	return binary.LittleEndian.Uint32(sha256Bytes[:4])
}

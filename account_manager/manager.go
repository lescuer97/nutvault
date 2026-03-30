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
	db           *database.SqliteDB
	signer       *signer.Signer
	caCertPEM    []byte
	caKeyPEM     []byte
	tlsConfigDir string
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

	if len(m.caCertPEM) > 0 && len(m.caKeyPEM) > 0 && m.tlsConfigDir != "" {
		derivedFP, err := m.ProvisionAccountCertificates(account.Id)
		if err != nil {
			return nil, fmt.Errorf("m.ProvisionAccountCertificates(account.Id): %w", err)
		}
		account.ClientPubkeyFP = derivedFP
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

func (m *Manager) UpdateKeyName(ctx context.Context, id string, name string) error {
	_ = ctx
	if m.db == nil {
		return fmt.Errorf("database is not configured")
	}
	return m.db.UpdateAccountName(id, name)
}

func (m *Manager) GetKeysFromNpub(pubkey *secp256k1.PublicKey) ([]database.Account, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database is not configured")
	}
	if pubkey == nil {
		return nil, fmt.Errorf("pubkey is required")
	}
	return m.db.GetAccountsByNpub(pubkey.SerializeCompressed())
}

func (m *Manager) GetKeysetsForAccount(ctx context.Context, accountID string) ([]database.Seed, error) {
	if m.db == nil || m.db.Db == nil {
		return nil, fmt.Errorf("database is not configured")
	}
	tx, err := m.db.Db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("m.db.Db.BeginTx(ctx, nil): %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	seeds, err := m.db.GetSeedsByAccountID(tx, accountID)
	if err != nil {
		return nil, fmt.Errorf("m.db.GetSeedsByAccountID(tx, accountID): %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("tx.Commit(): %w", err)
	}
	return seeds, nil
}

func (m *Manager) SetKeyActive(ctx context.Context, accountID string, active bool) error {
	_ = ctx
	if m.db == nil {
		return fmt.Errorf("database is not configured")
	}
	return m.db.UpdateAccountActive(accountID, active)
}

func (m *Manager) GetKeyActive(ctx context.Context, accountID string) (bool, error) {
	_ = ctx
	account, err := m.GetKeyByID(accountID)
	if err != nil {
		return false, err
	}
	return account.Active, nil
}

func (m *Manager) AccountBelongsToPubkey(ctx context.Context, accountID string, pubkey *btcec.PublicKey) (*database.Account, error) {
	_ = ctx
	if pubkey == nil {
		return nil, fmt.Errorf("pubkey is required")
	}
	account, err := m.GetKeyByID(accountID)
	if err != nil {
		return nil, err
	}
	if account.Npub == nil || !account.Npub.IsEqual(pubkey) {
		return nil, fmt.Errorf("account does not belong to pubkey")
	}
	return account, nil
}

func makeDerivation(pubkey *secp256k1.PublicKey, id []byte) uint32 {
	bytes := append([]byte{}, pubkey.SerializeCompressed()...)
	bytes = append(bytes, id...)
	sha256Bytes := sha256.Sum256(bytes)
	return binary.LittleEndian.Uint32(sha256Bytes[:4])
}

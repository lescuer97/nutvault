package accountmanager

import (
	"nutmix_remote_signer/database"

	"github.com/btcsuite/btcd/btcec/v2"
)


type Manager struct {
	db *database.SqliteDB
}

func NewManager(db *database.SqliteDB) Manager {
	return Manager{db: db}
}


func (m *Manager) MakeSignerKey(pubkey *btcec.PublicKey) error {
	return nil
}

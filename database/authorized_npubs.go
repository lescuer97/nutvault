package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type AuthorizedNpub struct {
	Active        bool                 `json:"active" cbor:"active"`
	Npub          *secp256k1.PublicKey `json:"npub"   cbor:"npub"`
	MaxKeys       uint64               `json:"max_keys"     cbor:"id"`
	CreatedAt     time.Time            `json:"created_at" cbor:"created_at"`
	DeactivatedAt *time.Time           `json:"deativated_at" cbor:"deativated_at"`
}

// Signature-related functions are commented out until signature handling
// is implemented correctly. See TODO/FIXME comments in the original
// implementation.

func (s *SqliteDB) CreateAuthorizedNpub(tx *sql.Tx, authNpub *AuthorizedNpub) error {
	stmt, err := tx.Prepare("INSERT INTO authorized_npubs (active, npub, max_keys, created_at, deativated_at) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(authNpub.Active, authNpub.Npub.SerializeCompressed(), authNpub.MaxKeys, time.Now().Unix(), nil)
	return err
}

func (s *SqliteDB) GetAllAuthorizedNpubs() ([]AuthorizedNpub, error) {
	stmt, err := s.Db.Prepare("SELECT active, npub, max_keys, created_at, deativated_at FROM authorized_npubs")
	if err != nil {
		return nil, fmt.Errorf(`s.Db.Prepare("SELECT active, npub, max_keys, created_at, deativated_at FROM authorized_npubs"). %w`, err)
	}
	defer stmt.Close()

	rows, err := stmt.Query()
	if err != nil {
		return nil, fmt.Errorf(`stmt.Query(args...). %w`, err)
	}
	defer rows.Close()

	authorizedNpubs := []AuthorizedNpub{}
	for rows.Next() {
		var authNpub AuthorizedNpub
		var created_at uint64
		var deleted_at *uint64
		var npub []byte
		err := rows.Scan(&authNpub.Active, &npub, &authNpub.MaxKeys, &created_at, &deleted_at)
		if err != nil {
			return nil, err
		}
		authNpub.CreatedAt = time.Unix(int64(created_at), 0)
		if deleted_at != nil {
			deactTime := time.Unix(int64(*deleted_at), 0)
			authNpub.DeactivatedAt = &deactTime
		}
		pubkey, err := btcec.ParsePubKey(npub)
		if err != nil {
			return nil, fmt.Errorf(`btcec.ParsePubKey(npub). %w`, err)
		}
		if len(npub) == 0 || npub == nil {
			log.Panicf("npub should have never been null at this point")
		}
		authNpub.Npub = pubkey
		authorizedNpubs = append(authorizedNpubs, authNpub)
	}
	return authorizedNpubs, nil
}

func (s *SqliteDB) GetAuthorizedNpubByNpub(tx *sql.Tx, npubToCheck *secp256k1.PublicKey) (AuthorizedNpub, error) {
	stmt, err := tx.Prepare("SELECT active, npub, max_keys, created_at, deativated_at FROM authorized_npubs WHERE npub = ? FOR UPDATE")
	if err != nil {
		return AuthorizedNpub{}, fmt.Errorf(`s.Db.Prepare("SELECT active, npub, max_keys, created_at, deativated_at FROM authorized_npubs  WHERE npub = ?"). %w`, err)
	}
	defer stmt.Close()

	row := stmt.QueryRow(npubToCheck.SerializeCompressed())

	var authNpub AuthorizedNpub
	var created_at uint64
	var deleted_at *uint64
	var npub []byte
	err = row.Scan(&authNpub.Active, &npub, &authNpub.MaxKeys, &created_at, &deleted_at)
	if err != nil {
		return AuthorizedNpub{}, err
	}
	authNpub.CreatedAt = time.Unix(int64(created_at), 0)
	if deleted_at != nil {
		deactTime := time.Unix(int64(*deleted_at), 0)
		authNpub.DeactivatedAt = &deactTime
	}

	pubkey, err := btcec.ParsePubKey(npub)
	if err != nil {
		return AuthorizedNpub{}, fmt.Errorf(`btcec.ParsePubKey(npub). %w`, err)
	}

	if len(npub) == 0 || npub == nil {
		log.Panicf("npub should have never been null at this point")
	}
	authNpub.Npub = pubkey

	return authNpub, nil
}

func (s *SqliteDB) UpdateAuthorizedNpubActive(tx *sql.Tx, npub *secp256k1.PublicKey, active bool) error {
	stmt, err := tx.Prepare("UPDATE keys SET active = ? WHERE id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(active, npub.SerializeCompressed())
	return err
}

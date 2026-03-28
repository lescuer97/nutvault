package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Account struct {
	Active         bool                 `json:"active"`
	Npub           *secp256k1.PublicKey `json:"npub"`
	Id             string               `json:"id"`
	Name           string               `json:"name"`
	ClientPubkeyFP string               `json:"client_pubkey_fp"`
	Derivation     uint32               `json:"derivation"`
	CreatedAt      int64                `json:"created_at"`
}

type AccountWithSeeds struct {
	Account Account
	Seeds   []Seed
}

func (s *SqliteDB) CreateAccount(tx *sql.Tx, account *Account) error {
	stmt, err := tx.Prepare("INSERT INTO accounts (active, npub, id, name, derivation, created_at, client_pubkey_fp) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return fmt.Errorf("prepare CreateAccount: %w", err)
	}
	defer func() {
		_ = stmt.Close()
	}()

	var npub []byte
	if account.Npub != nil {
		npub = account.Npub.SerializeCompressed()
	}

	_, err = stmt.Exec(account.Active, npub, account.Id, account.Name, account.Derivation, account.CreatedAt, nullableString(account.ClientPubkeyFP))
	if err != nil {
		return fmt.Errorf("exec CreateAccount: %w", err)
	}
	return nil
}

func (s *SqliteDB) GetAccountByID(id string) (*Account, error) {
	row := s.Db.QueryRow("SELECT active, npub, id, name, derivation, created_at, client_pubkey_fp FROM accounts WHERE id = ?", id)
	account, err := scanAccount(row)
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func (s *SqliteDB) GetAllAccounts() ([]Account, error) {
	rows, err := s.Db.Query("SELECT active, npub, id, name, derivation, created_at, client_pubkey_fp FROM accounts ORDER BY created_at ASC")
	if err != nil {
		return nil, fmt.Errorf("query GetAllAccounts: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	accounts := []Account{}
	for rows.Next() {
		account, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}

	return accounts, rows.Err()
}

func (s *SqliteDB) GetAccountByClientPubkeyFP(ctx context.Context, fp string) (Account, error) {
	row := s.Db.QueryRowContext(ctx, "SELECT active, npub, id, name, derivation, created_at, client_pubkey_fp FROM accounts WHERE client_pubkey_fp = ?", fp)
	return scanAccount(row)
}

func (s *SqliteDB) UpdateAccountActive(id string, active bool) error {
	stmt, err := s.Db.Prepare("UPDATE accounts SET active = ? WHERE id = ?")
	if err != nil {
		return fmt.Errorf("prepare UpdateAccountActive: %w", err)
	}
	defer func() {
		_ = stmt.Close()
	}()

	_, err = stmt.Exec(active, id)
	if err != nil {
		return fmt.Errorf("exec UpdateAccountActive: %w", err)
	}
	return nil
}

func (s *SqliteDB) GetAccountsWithSeeds() ([]AccountWithSeeds, error) {
	query := `
		SELECT
			a.active, a.npub, a.id, a.name, a.derivation, a.created_at, a.client_pubkey_fp,
			s.active, s.unit, s.id, s.created_at, s.input_fee_ppk, s.version, s.legacy, s.account_id, s.derivation_path, s.amounts, s.final_expiry
		FROM accounts a
		LEFT JOIN seeds s ON a.id = s.account_id
		ORDER BY a.created_at ASC, s.version DESC
	`

	rows, err := s.Db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query GetAccountsWithSeeds: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	accountsMap := make(map[string]*AccountWithSeeds)
	orderedIDs := []string{}

	for rows.Next() {
		var npub []byte
		var clientFP sql.NullString
		account := Account{}

		var seedActive sql.NullBool
		var seedUnit sql.NullString
		var seedID sql.NullString
		var seedCreatedAt sql.NullInt64
		var seedInputFeePpk sql.NullInt64
		var seedVersion sql.NullInt64
		var seedLegacy sql.NullBool
		var seedAccountID sql.NullString
		var seedDerivationPath sql.NullString
		var seedAmounts sql.NullString
		var seedFinalExpiry sql.NullInt64

		err := rows.Scan(
			&account.Active, &npub, &account.Id, &account.Name, &account.Derivation, &account.CreatedAt, &clientFP,
			&seedActive, &seedUnit, &seedID, &seedCreatedAt, &seedInputFeePpk, &seedVersion, &seedLegacy, &seedAccountID, &seedDerivationPath, &seedAmounts, &seedFinalExpiry,
		)
		if err != nil {
			return nil, fmt.Errorf("scan GetAccountsWithSeeds row: %w", err)
		}

		if len(npub) > 0 {
			pubkey, err := btcec.ParsePubKey(npub)
			if err != nil {
				return nil, fmt.Errorf("btcec.ParsePubKey(npub): %w", err)
			}
			account.Npub = pubkey
		}
		if clientFP.Valid {
			account.ClientPubkeyFP = clientFP.String
		}

		if _, ok := accountsMap[account.Id]; !ok {
			accountsMap[account.Id] = &AccountWithSeeds{Account: account, Seeds: []Seed{}}
			orderedIDs = append(orderedIDs, account.Id)
		}

		if seedID.Valid {
			seed := Seed{
				Active:         seedActive.Bool,
				Unit:           seedUnit.String,
				Id:             seedID.String,
				CreatedAt:      seedCreatedAt.Int64,
				InputFeePpk:    uint(seedInputFeePpk.Int64),
				Version:        uint64(seedVersion.Int64),
				Legacy:         seedLegacy.Bool,
				AccountID:      seedAccountID.String,
				DerivationPath: seedDerivationPath.String,
			}
			if seedFinalExpiry.Valid {
				timestamp := time.Unix(seedFinalExpiry.Int64, 0)
				seed.FinalExpiry = &timestamp
			}
			if err := json.Unmarshal([]byte(seedAmounts.String), &seed.Amounts); err != nil {
				return nil, fmt.Errorf("json.Unmarshal(seed.Amounts): %w", err)
			}
			accountsMap[account.Id].Seeds = append(accountsMap[account.Id].Seeds, seed)
		}
	}

	result := make([]AccountWithSeeds, 0, len(orderedIDs))
	for _, id := range orderedIDs {
		result = append(result, *accountsMap[id])
	}

	return result, rows.Err()
}

func scanAccount(scanner interface{ Scan(dest ...any) error }) (Account, error) {
	account := Account{}
	var npub []byte
	var clientFP sql.NullString
	err := scanner.Scan(&account.Active, &npub, &account.Id, &account.Name, &account.Derivation, &account.CreatedAt, &clientFP)
	if err != nil {
		return account, err
	}
	if len(npub) > 0 {
		pubkey, err := btcec.ParsePubKey(npub)
		if err != nil {
			return account, fmt.Errorf("btcec.ParsePubKey(npub): %w", err)
		}
		account.Npub = pubkey
	}
	if clientFP.Valid {
		account.ClientPubkeyFP = clientFP.String
	}
	return account, nil
}

func nullableString(value string) sql.NullString {
	if value == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}

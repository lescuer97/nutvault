package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type Account struct {
	Active         bool   `json:"active" cbor:"active"`
	Npub           []byte `json:"npub"   cbor:"npub"`
	Id             string `json:"id"     cbor:"id"`
	Name           string `json:"name"   cbor:"name" db:"name"`
	ClientPubkeyFP string `json:"client_pubkey_fp" db:"client_pubkey_fp" cbor:"client_pubkey_fp"`
	// NOTE: derivation = sha256sum(npub + id)
	Derivation uint32 `json:"derivation" cbor:"derivation"`
	CreatedAt  int64  `json:"created_at" cbor:"created_at"`
	// Signature removed pending implementation
	// Signature  *schnorr.Signature `json:"signature" cbor:"-"`
}

// Signature-related functions are commented out until signature handling
// is implemented correctly. See TODO/FIXME comments in the original
// implementation.

func (s *SqliteDB) CreateAccount(account *Account) error {
	stmt, err := s.Db.Prepare("INSERT INTO accounts (active, npub, id, name, derivation, created_at, client_pubkey_fp) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(account.Active, account.Npub, account.Id, account.Name, account.Derivation, time.Now().Unix(), account.ClientPubkeyFP)
	return err
}

func (s *SqliteDB) FlipAccountActive(id string) error {
	stmt, err := s.Db.Prepare("UPDATE accounts SET active = NOT active WHERE id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(id)
	return err
}

func (s *SqliteDB) GetAccountById(id string) (*Account, error) {
	row := s.Db.QueryRow("SELECT active, npub, id, name, derivation, created_at, client_pubkey_fp FROM accounts WHERE id = ?", id)

	var account Account
	err := row.Scan(&account.Active, &account.Npub, &account.Id, &account.Name, &account.Derivation, &account.CreatedAt, &account.ClientPubkeyFP)
	if err != nil {
		return nil, err
	}

	return &account, nil
}

func (s *SqliteDB) GetAccountsByNpub(npub []byte) ([]Account, error) {
	accounts := []Account{}
	stmt, err := s.Db.Prepare("SELECT active, npub, id, name, derivation, created_at, client_pubkey_fp FROM accounts WHERE npub = ?")
	if err != nil {
		return accounts, fmt.Errorf(`s.Db.Prepare("SELECT active, npub, id, name, derivation, created_at, client_pubkey_fp FROM accounts WHERE npub = ?"). %w`, err)
	}
	defer stmt.Close()

	rows, err := stmt.Query(npub)
	if err != nil {
		return accounts, fmt.Errorf(`stmt.Query(args...). %w`, err)
	}
	defer rows.Close()

	for rows.Next() {
		var account Account
		err := rows.Scan(&account.Active, &account.Npub, &account.Id, &account.Name, &account.Derivation, &account.CreatedAt, &account.ClientPubkeyFP)
		if err != nil {
			return nil, err
		}

		accounts = append(accounts, account)
	}
	return accounts, nil
}

func (s *SqliteDB) GetAccountByNpub(npub []byte) (*Account, error) {
	row := s.Db.QueryRow("SELECT active, npub, id, name, derivation, created_at, client_pubkey_fp FROM accounts WHERE npub = ?", npub)

	var account Account
	err := row.Scan(&account.Active, &account.Npub, &account.Id, &account.Name, &account.Derivation, &account.CreatedAt, &account.ClientPubkeyFP)
	if err != nil {
		return nil, err
	}

	return &account, nil
}

func (s *SqliteDB) GetAccountByClientPubkeyFP(ctx context.Context, fp string) (Account, error) {
	row := s.Db.QueryRow("SELECT active, npub, id, name, derivation, created_at, client_pubkey_fp FROM accounts WHERE client_pubkey_fp = ?", fp)

	var account Account
	err := row.Scan(&account.Active, &account.Npub, &account.Id, &account.Name, &account.Derivation, &account.CreatedAt, &account.ClientPubkeyFP)
	if err != nil {
		return Account{}, err
	}

	return account, nil
}

// UpdateAccountName updates the name of an account identified by id.
func (s *SqliteDB) UpdateAccountName(id string, name string) error {
	stmt, err := s.Db.Prepare("UPDATE accounts SET name = ? WHERE id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(name, id)
	return err
}

// UpdateAccountName updates the name of an account identified by id.
func (s *SqliteDB) UpdateAccountActive(id string, active bool) error {
	stmt, err := s.Db.Prepare("UPDATE accounts SET active = ? WHERE id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(active, id)
	return err
}

type AccountWithSeeds struct {
	*Account
	Seeds []Seed `json:"seeds"`
}

func (s *SqliteDB) GetAccountsWithSeeds() ([]AccountWithSeeds, error) {
	query := `
		SELECT
			a.active, a.npub, a.id, a.name, a.derivation, a.created_at,
			s.active, s.unit, s.id, s.created_at, s.input_fee_ppk, s.version, s.legacy, s.amounts, s.account_id
		FROM
			accounts a
		LEFT JOIN
			seeds s ON a.id = s.account_id`

	rows, err := s.Db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	accountsMap := make(map[string]*AccountWithSeeds)

	for rows.Next() {
		var account Account
		var seed Seed
		var seedActive sql.NullBool
		var seedUnit, seedId, seedAmounts, seedAccountId sql.NullString
		var seedCreatedAt, seedInputFeePpk, seedVersion sql.NullInt64
		var seedLegacy sql.NullBool
		err := rows.Scan(
			&account.Active, &account.Npub, &account.Id, &account.Name, &account.Derivation, &account.CreatedAt,
			&seedActive, &seedUnit, &seedId, &seedCreatedAt, &seedInputFeePpk, &seedVersion, &seedLegacy, &seedAmounts, &seedAccountId,
		)
		if err != nil {
			return nil, err
		}

		if _, ok := accountsMap[account.Id]; !ok {
			accountsMap[account.Id] = &AccountWithSeeds{
				Account: &account,
				Seeds:   []Seed{},
			}
		}

		if seedId.Valid {
			seed = Seed{
				Active:      seedActive.Bool,
				Unit:        seedUnit.String,
				Id:          seedId.String,
				CreatedAt:   seedCreatedAt.Int64,
				InputFeePpk: uint(seedInputFeePpk.Int64),
				Version:     uint64(seedVersion.Int64),
				Legacy:      seedLegacy.Bool,
				AccountId:   seedAccountId.String,
			}
			err := cbor.Unmarshal([]byte(seedAmounts.String), &seed.Amounts)
			if err != nil {
				return nil, fmt.Errorf(`cbor.Unmarshal( []byte(amountsStr), &seed.Amounts) %w`, err)
			}
			accountsMap[account.Id].Seeds = append(accountsMap[account.Id].Seeds, seed)
		}
	}

	result := []AccountWithSeeds{}
	for _, v := range accountsMap {
		result = append(result, *v)
	}
	return result, nil
}

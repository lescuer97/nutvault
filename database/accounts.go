package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/fxamacker/cbor/v2"
)

type Account struct {
	Active bool   `json:"active"`
	Npub   []byte `json:"npub"`
	Id     string `json:"id"`
	// NOTE: derivation = sha256sum(npub + id)
	Derivation uint32 `json:"derivation"`
	CreatedAt  int64  `json:"created_at"`
	Signature  []byte `json:"signature"`
}

func (a *Account) VerifySignature(pubkey btcec.PublicKey) bool {

	log.Panicf("need to implement Signature Verification")
	return false
}

type AuthToken struct {
	Id        string `json:"id"`
	AccountId string `json:"account_id"`
	Active    bool   `json:"active"`
	Token     string `json:"token"`
	CreatedAt int64  `json:"created_at"`
	Signature []byte `json:"signature"`
}

func (a *AuthToken) VerifySignature(pubkey btcec.PublicKey) bool {

	log.Panicf("need to implement Signature Verification")
	return false
}

func (s *SqliteDB) CreateAccount(account *Account) error {
	stmt, err := s.Db.Prepare("INSERT INTO accounts (active, npub, id, derivation, created_at, signature) VALUES (?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(account.Active, account.Npub, account.Id, account.Derivation, time.Now().Unix(), account.Signature)
	return err
}

func (s *SqliteDB) CreateAuthToken(authToken *AuthToken) error {
	stmt, err := s.Db.Prepare("INSERT INTO auth_tokens (id, account_id, active, token, created_at, signature) VALUES (?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(authToken.Id, authToken.AccountId, authToken.Active, authToken.Token, time.Now().Unix(), authToken.Signature)
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

func (s *SqliteDB) FlipAuthTokenActive(id string) error {
	stmt, err := s.Db.Prepare("UPDATE auth_tokens SET active = NOT active WHERE id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(id)
	return err
}

func (s *SqliteDB) GetAccountById(id string) (*Account, error) {
	row := s.Db.QueryRow("SELECT active, npub, id, derivation, created_at, signature FROM accounts WHERE id = ?", id)

	var account Account
	err := row.Scan(&account.Active, &account.Npub, &account.Id, &account.Derivation, &account.CreatedAt, &account.Signature)
	if err != nil {
		return nil, err
	}

	return &account, nil
}

func (s *SqliteDB) GetAuthTokenById(id string) (*AuthToken, error) {
	row := s.Db.QueryRow("SELECT id, account_id, active, token, created_at, signature FROM auth_tokens WHERE id = ?", id)

	var authToken AuthToken
	err := row.Scan(&authToken.Id, &authToken.AccountId, &authToken.Active, &authToken.Token, &authToken.CreatedAt, &authToken.Signature)
	if err != nil {
		return nil, err
	}

	return &authToken, nil
}

func (s *SqliteDB) GetAccountByNpub(npub []byte) (*Account, error) {
	row := s.Db.QueryRow("SELECT active, npub, id, derivation, created_at, signature FROM accounts WHERE npub = ?", npub)

	var account Account
	err := row.Scan(&account.Active, &account.Npub, &account.Id, &account.Derivation, &account.CreatedAt, &account.Signature)
	if err != nil {
		return nil, err
	}

	return &account, nil
}

func (s *SqliteDB) GetAuthTokenByToken(token string) (*AuthToken, error) {
	row := s.Db.QueryRow("SELECT id, account_id, active, token, created_at, signature FROM auth_tokens WHERE token = ?", token)

	var authToken AuthToken
	err := row.Scan(&authToken.Id, &authToken.AccountId, &authToken.Active, &authToken.Token, &authToken.CreatedAt, &authToken.Signature)
	if err != nil {
		return nil, err
	}

	return &authToken, nil
}

type AccountWithSeeds struct {
	Account
	Seeds []Seed `json:"seeds"`
}

func (s *SqliteDB) GetAccountsWithSeeds() ([]AccountWithSeeds, error) {
	query := `
		SELECT
			a.active, a.npub, a.id, a.derivation, a.created_at, a.signature,
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
			&account.Active, &account.Npub, &account.Id, &account.Derivation, &account.CreatedAt, &account.Signature,
			&seedActive, &seedUnit, &seedId, &seedCreatedAt, &seedInputFeePpk, &seedVersion, &seedLegacy, &seedAmounts, &seedAccountId,
		)
		if err != nil {
			return nil, err
		}

		if _, ok := accountsMap[account.Id]; !ok {
			accountsMap[account.Id] = &AccountWithSeeds{
				Account: account,
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
				Version:     int(seedVersion.Int64),
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
	if err = rows.Err(); err != nil {
		return nil, err
	}

	accountsWithSeeds := make([]AccountWithSeeds, 0, len(accountsMap))
	for _, accountWithSeeds := range accountsMap {
		accountsWithSeeds = append(accountsWithSeeds, *accountWithSeeds)
	}

	return accountsWithSeeds, nil
}

package database

import (
	"time"
)

type Account struct {
	Active     bool   `json:"active"`
	Npub       []byte `json:"npub"`
	Id         string `json:"id"`
	Derivation string `json:"derivation"`
	CreatedAt  int64  `json:"created_at"`
	Signature  []byte `json:"signature"`
}

type AuthToken struct {
	Id        string `json:"id"`
	AccountId string `json:"account_id"`
	Active    bool   `json:"active"`
	Token     string `json:"token"`
	CreatedAt int64  `json:"created_at"`
	Signature []byte `json:"signature"`
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

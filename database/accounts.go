package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
	"github.com/fxamacker/cbor/v2"
)

type Account struct {
	Active         bool   `json:"active" cbor:"active"`
	Npub           []byte `json:"npub"   cbor:"npub"`
	Id             string `json:"id"     cbor:"id"`
	ClientPubkeyFP string `json:"client_pubkey_fp" db:"client_pubkey_fp" cbor:"client_pubkey_fp"`
	// NOTE: derivation = sha256sum(npub + id)
	Derivation uint32             `json:"derivation" cbor:"derivation"`
	CreatedAt  int64              `json:"created_at" cbor:"created_at"`
	Signature  *schnorr.Signature `json:"signature" cbor:"-"`
}

func (a *Account) VerifySignature(pubkey btcec.PublicKey) (bool, error) {
	msg, err := cbor.Marshal(a)
	if err != nil {
		return false, fmt.Errorf("cbor.Marshal(a). %w", err)
	}
	hash := sha256.Sum256(msg)
	return a.Signature.Verify(hash[:], &pubkey), nil
}

func (a *Account) Sign(privKey *btcec.PrivateKey) error {
	msg, err := cbor.Marshal(a)
	if err != nil {
		return fmt.Errorf("cbor.Marshal(a). %w", err)
	}
	hash := sha256.Sum256(msg)
	signature, err := schnorr.Sign(privKey, hash[:])
	if err != nil {
		return fmt.Errorf("schnorr.Sign(privKey, hash[:]). %w", err)
	}

	a.Signature = signature
	log.Panicf("need to implement Signature Verification")
	return nil
}

func (s *SqliteDB) CreateAccount(account *Account) error {
	stmt, err := s.Db.Prepare("INSERT INTO accounts (active, npub, id, derivation, created_at, signature, client_pubkey_fp) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(account.Active, account.Npub, account.Id, account.Derivation, time.Now().Unix(), account.Signature.Serialize(), account.ClientPubkeyFP)
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
	row := s.Db.QueryRow("SELECT active, npub, id, derivation, created_at, signature, client_pubkey_fp FROM accounts WHERE id = ?", id)

	var account Account
	var sigBytes []byte
	err := row.Scan(&account.Active, &account.Npub, &account.Id, &account.Derivation, &account.CreatedAt, &sigBytes, &account.ClientPubkeyFP)
	if err != nil {
		return nil, err
	}

	// FIX: Uncomment signature setup and fix signature
	// sig, err := schnorr.ParseSignature(sigBytes)
	// if err != nil {
	//  return nil, fmt.Errorf("schnorr.ParseSignature(sigBytes). %w", err)
	// }
	//authToken.Signature = nil

	return &account, nil
}

func (s *SqliteDB) GetAccountsByNpub(npub []byte) ([]Account, error) {
	accounts := []Account{}
	stmt, err := s.Db.Prepare("SELECT active, npub, id, derivation, created_at, signature, client_pubkey_fp FROM accounts WHERE npub = ?")
	if err != nil {
		return accounts, fmt.Errorf(`s.Db.Prepare("SELECT active, npub, id, derivation, created_at, signature, client_pubkey_fp FROM accounts WHERE npub = ?"). %w`, err)
	}
	defer stmt.Close()

	rows, err := stmt.Query(npub)
	if err != nil {
		return accounts, fmt.Errorf(`stmt.Query(args...). %w`, err)
	}
	defer rows.Close()

	for rows.Next() {
		var account Account
		var sigBytes []byte
		err := rows.Scan(&account.Active, &account.Npub, &account.Id, &account.Derivation, &account.CreatedAt, &sigBytes)
		if err != nil {
			return nil, err
		}

		sig, err := schnorr.ParseSignature(sigBytes)
		if err != nil {
			return nil, fmt.Errorf("schnorr.ParseSignature(sigBytes). %w", err)
		}
		account.Signature = sig

		accounts = append(accounts, account)
	}
	return accounts, nil
}
func (s *SqliteDB) GetAccountByNpub(npub []byte) (*Account, error) {
	row := s.Db.QueryRow("SELECT active, npub, id, derivation, created_at, signature, client_pubkey_fp FROM accounts WHERE npub = ?", npub)

	var account Account
	var sigBytes []byte
	err := row.Scan(&account.Active, &account.Npub, &account.Id, &account.Derivation, &account.CreatedAt, &sigBytes)
	if err != nil {
		return nil, err
	}

	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return nil, fmt.Errorf("schnorr.ParseSignature(sigBytes). %w", err)
	}
	account.Signature = sig

	return &account, nil
}

func (s *SqliteDB) GetAccountByClientPubkeyFP(ctx context.Context, fp string) (Account, error) {
	row := s.Db.QueryRow("SELECT active, npub, id, derivation, created_at, signature, client_pubkey_fp FROM accounts WHERE client_pubkey_fp = ?", fp)

	var account Account
	var sigBytes []byte
	err := row.Scan(&account.Active, &account.Npub, &account.Id, &account.Derivation, &account.CreatedAt, &sigBytes, &account.ClientPubkeyFP)
	if err != nil {
		return Account{}, err
	}

	// FIXME: signature parsing
	account.Signature = nil

	return account, nil
}

type AccountWithSeeds struct {
	*Account
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
		var sigBytes []byte
		err := rows.Scan(
			&account.Active, &account.Npub, &account.Id, &account.Derivation, &account.CreatedAt, &sigBytes,
			&seedActive, &seedUnit, &seedId, &seedCreatedAt, &seedInputFeePpk, &seedVersion, &seedLegacy, &seedAmounts, &seedAccountId,
		)
		if err != nil {
			return nil, err
		}
		// FIX: Uncomment signature setup and fix signature
		// sig, err := schnorr.ParseSignature(sigBytes)
		// if err != nil {
		//  return nil, fmt.Errorf("schnorr.ParseSignature(sigBytes). %w", err)
		// }
		account.Signature = nil

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
	if err = rows.Err(); err != nil {
		return nil, err
	}

	accountsWithSeeds := make([]AccountWithSeeds, 0, len(accountsMap))
	for _, accountWithSeeds := range accountsMap {
		accountsWithSeeds = append(accountsWithSeeds, *accountWithSeeds)
	}

	return accountsWithSeeds, nil
}

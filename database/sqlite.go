package database

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"time"

	"github.com/lescuer97/nutmix/api/cashu"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pressly/goose/v3"
)

const DefaultAccountID = "default"

type Seed struct {
	FinalExpiry    *time.Time `db:"final_expiry"`
	Unit           string
	Id             string
	AccountID      string `db:"account_id"`
	DerivationPath string
	Amounts        []uint64 `db:"amounts"`
	CreatedAt      int64
	Version        uint64
	InputFeePpk    uint `json:"input_fee_ppk" db:"input_fee_ppk"`
	Active         bool
	Legacy         bool
}

type SqliteDB struct {
	Db *sql.DB
}

//go:embed migrations/*.sql
var embedMigrations embed.FS

func DatabaseSetup(ctx context.Context, databaseDir string) (SqliteDB, error) {
	var sqlitedb SqliteDB

	slog.Debug("Opening database")
	db, err := sql.Open("sqlite3", databaseDir+"/"+"app.db")
	if err != nil {
		return sqlitedb, fmt.Errorf(`sql.Open("sqlite3", string + "app.db" ). %w`, err)
	}
	goose.SetBaseFS(embedMigrations)

	if err := goose.SetDialect("sqlite3"); err != nil {
		log.Fatalf("Error setting dialect: %v", err)
	}

	slog.Debug("Running migrations")
	if err := goose.Up(db, "migrations"); err != nil {
		log.Fatalf("Error running migrations: %v", err)
	}

	if err := ensureCompatibilitySchema(ctx, db); err != nil {
		return sqlitedb, fmt.Errorf("ensureCompatibilitySchema(db): %w", err)
	}

	db.SetMaxOpenConns(1)
	sqlitedb.Db = db

	return sqlitedb, nil
}

func ensureCompatibilitySchema(ctx context.Context, db *sql.DB) error {
	if err := ensureAccountsTable(ctx, db); err != nil {
		return err
	}
	if err := ensureSeedsAccountColumn(ctx, db); err != nil {
		return err
	}
	if err := ensureDefaultAccount(ctx, db); err != nil {
		return err
	}
	return nil
}

func ensureAccountsTable(ctx context.Context, db *sql.DB) error {
	exists, err := tableExists(ctx, db, "accounts")
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	_, err = db.ExecContext(ctx, `
		CREATE TABLE accounts (
			id text NOT NULL,
			active bool NOT NULL,
			name text NOT NULL DEFAULT '',
			created_at int8 NOT NULL,
			derivation int8 NOT NULL,
			npub blob,
			client_pubkey_fp text UNIQUE,
			CONSTRAINT accounts_pk PRIMARY KEY (id),
			CONSTRAINT accounts_derivation_unique UNIQUE (derivation)
		);
	`)
	if err != nil {
		return fmt.Errorf("creating accounts table: %w", err)
	}

	_, err = db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_accounts_id ON accounts (id);
		CREATE INDEX IF NOT EXISTS idx_accounts_client_pubkey_fp ON accounts (client_pubkey_fp);
	`)
	if err != nil {
		return fmt.Errorf("creating accounts indexes: %w", err)
	}

	return nil
}

func ensureSeedsAccountColumn(ctx context.Context, db *sql.DB) error {
	exists, err := columnExists(ctx, db, "seeds", "account_id")
	if err != nil {
		return err
	}
	if exists {
		_, err = db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_seed_account_id ON seeds (account_id)`)
		return err
	}

	_, err = db.ExecContext(ctx, `ALTER TABLE seeds ADD COLUMN account_id text`)
	if err != nil {
		return fmt.Errorf("alter seeds add account_id: %w", err)
	}

	_, err = db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_seed_account_id ON seeds (account_id)`)
	if err != nil {
		return fmt.Errorf("create idx_seed_account_id: %w", err)
	}

	return nil
}

func ensureDefaultAccount(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO accounts (id, active, name, created_at, derivation)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING
	`, DefaultAccountID, true, "default", time.Now().Unix(), 0)
	if err != nil {
		return fmt.Errorf("insert default account: %w", err)
	}

	_, err = db.ExecContext(ctx, `UPDATE seeds SET account_id = ? WHERE account_id IS NULL OR account_id = ''`, DefaultAccountID)
	if err != nil {
		return fmt.Errorf("backfill seeds.account_id: %w", err)
	}

	return nil
}

func tableExists(ctx context.Context, db *sql.DB, table string) (bool, error) {
	var name string
	err := db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name = ?`, table).Scan(&name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("tableExists(%s): %w", table, err)
	}
	return true, nil
}

func columnExists(ctx context.Context, db *sql.DB, table string, column string) (bool, error) {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return false, fmt.Errorf("PRAGMA table_info(%s): %w", table, err)
	}
	defer func() {
		_ = rows.Close()
	}()

	for rows.Next() {
		var cid int
		var name string
		var dataType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
			return false, fmt.Errorf("scan table_info(%s): %w", table, err)
		}
		if name == column {
			return true, nil
		}
	}

	return false, rows.Err()
}

func scanSeed(scanner interface{ Scan(dest ...any) error }, includeAccountID bool) (Seed, error) {
	var seed Seed
	amountsStr := ""
	var timeUnix *int64

	if includeAccountID {
		if err := scanner.Scan(&seed.CreatedAt, &seed.Active, &seed.Version, &seed.Unit, &seed.Id, &seed.InputFeePpk, &seed.Legacy, &seed.AccountID, &seed.DerivationPath, &amountsStr, &timeUnix); err != nil {
			return seed, err
		}
	} else {
		if err := scanner.Scan(&seed.CreatedAt, &seed.Active, &seed.Version, &seed.Unit, &seed.Id, &seed.InputFeePpk, &seed.Legacy, &seed.DerivationPath, &amountsStr, &timeUnix); err != nil {
			return seed, err
		}
		seed.AccountID = DefaultAccountID
	}

	if timeUnix != nil {
		timestamp := time.Unix(*timeUnix, 0)
		seed.FinalExpiry = &timestamp
	}

	if err := json.Unmarshal([]byte(amountsStr), &seed.Amounts); err != nil {
		return seed, err
	}

	return seed, nil
}

func (sq *SqliteDB) GetAllSeeds() ([]Seed, error) {
	seeds := []Seed{}
	stmt, err := sq.Db.Prepare(`SELECT created_at, active, version, unit, id, input_fee_ppk, legacy, account_id, derivation_path, amounts, final_expiry FROM seeds ORDER BY version DESC`)
	if err != nil {
		return seeds, fmt.Errorf("prepare GetAllSeeds: %w", err)
	}
	defer func() {
		_ = stmt.Close()
	}()

	rows, err := stmt.Query()
	if err != nil {
		return seeds, fmt.Errorf("query GetAllSeeds: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	for rows.Next() {
		seed, err := scanSeed(rows, true)
		if err != nil {
			return seeds, fmt.Errorf("scan GetAllSeeds row: %w", err)
		}
		seeds = append(seeds, seed)
	}
	return seeds, rows.Err()
}

func (sq *SqliteDB) GetSeedsByUnit(tx *sql.Tx, unit cashu.Unit) ([]Seed, error) {
	return sq.getSeedsByQuery(tx, "SELECT created_at, active, version, unit, id, input_fee_ppk, legacy, account_id, derivation_path, amounts, final_expiry FROM seeds WHERE unit = $1", strings.ToUpper(unit.String()))
}

func (sq *SqliteDB) GetSeedsByAccountID(tx *sql.Tx, accountID string) ([]Seed, error) {
	return sq.getSeedsByQuery(tx, "SELECT created_at, active, version, unit, id, input_fee_ppk, legacy, account_id, derivation_path, amounts, final_expiry FROM seeds WHERE account_id = $1 ORDER BY version DESC", accountID)
}

func (sq *SqliteDB) GetSeedsByAccountAndUnit(tx *sql.Tx, accountID string, unit cashu.Unit) ([]Seed, error) {
	return sq.getSeedsByQuery(tx, "SELECT created_at, active, version, unit, id, input_fee_ppk, legacy, account_id, derivation_path, amounts, final_expiry FROM seeds WHERE account_id = $1 AND unit = $2 ORDER BY version DESC", accountID, strings.ToUpper(unit.String()))
}

func (sq *SqliteDB) getSeedsByQuery(tx *sql.Tx, query string, args ...any) ([]Seed, error) {
	seeds := []Seed{}
	stmt, err := tx.Prepare(query)
	if err != nil {
		return seeds, fmt.Errorf("prepare seed query: %w", err)
	}
	defer func() {
		_ = stmt.Close()
	}()

	rows, err := stmt.Query(args...)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return seeds, nil
		}
		return seeds, fmt.Errorf("query seeds: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	for rows.Next() {
		seed, err := scanSeed(rows, true)
		if err != nil {
			return seeds, fmt.Errorf("scan seed row: %w", err)
		}
		seeds = append(seeds, seed)
	}

	return seeds, rows.Err()
}

func (sq *SqliteDB) SaveNewSeed(tx *sql.Tx, seed Seed) error {
	tries := 0
	amounts, err := json.Marshal(seed.Amounts)
	if err != nil {
		return fmt.Errorf("json.Marshal(seed.Amounts): %w", err)
	}

	var unixTimestamp *int64
	if seed.FinalExpiry != nil {
		timestamp := seed.FinalExpiry.Unix()
		unixTimestamp = &timestamp
	}

	accountID := seed.AccountID
	if accountID == "" {
		accountID = DefaultAccountID
	}

	for {
		tries += 1
		_, err := tx.Exec("INSERT INTO seeds (active, created_at, unit, id, version, input_fee_ppk, legacy, account_id, derivation_path, amounts, final_expiry) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)", seed.Active, seed.CreatedAt, seed.Unit, seed.Id, seed.Version, seed.InputFeePpk, seed.Legacy, accountID, seed.DerivationPath, string(amounts), unixTimestamp)

		switch {
		case err != nil && tries < 3:
			continue
		case err != nil && tries >= 3:
			return fmt.Errorf("insert seed %s: %w", seed.Id, err)
		case err == nil:
			return nil
		}
	}
}

func (sq *SqliteDB) UpdateSeedsActiveStatus(tx *sql.Tx, seeds []Seed) error {
	stmt, err := tx.Prepare("UPDATE seeds SET active = ? WHERE id = ?")
	if err != nil {
		return fmt.Errorf("UPDATE seeds SET active = ? WHERE id = ?: %w", err)
	}
	defer func() {
		_ = stmt.Close()
	}()

	for _, seed := range seeds {
		if _, err = stmt.Exec(seed.Active, seed.Id); err != nil {
			return fmt.Errorf("exec UpdateSeedsActiveStatus for seed ID %s: %w", seed.Id, err)
		}
	}

	return nil
}

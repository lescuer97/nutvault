package database

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/lescuer97/nutmix/api/cashu"
	_ "github.com/mattn/go-sqlite3"
)

func TestDatabaseSetupCreatesAccountsSchema(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	sqlite, err := DatabaseSetup(ctx, dir)
	if err != nil {
		t.Fatalf("DatabaseSetup(ctx, dir): %v", err)
	}
	defer func() { _ = sqlite.Db.Close() }()

	assertTableExists(t, sqlite.Db, "accounts")
	assertColumnExists(t, sqlite.Db, "seeds", "account_id")
	assertIndexExists(t, sqlite.Db, "idx_seed_account_id")
	assertIndexExists(t, sqlite.Db, "sqlite_autoindex_accounts_2")

	account, err := sqlite.GetAccountByID(DefaultAccountID)
	if err != nil {
		t.Fatalf("GetAccountByID(DefaultAccountID): %v", err)
	}
	if account.Derivation != 0 {
		t.Fatalf("default account derivation = %d, want 0", account.Derivation)
	}
}

func TestDatabaseSetupBackfillsDefaultAccountOnLegacySchema(t *testing.T) {
	dir := t.TempDir()
	legacyDB, err := sql.Open("sqlite3", filepath.Join(dir, "app.db"))
	if err != nil {
		t.Fatalf("sql.Open legacy db: %v", err)
	}
	defer func() { _ = legacyDB.Close() }()

	_, err = legacyDB.Exec(`
		CREATE TABLE goose_db_version (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			version_id bigint NOT NULL,
			is_applied boolean NOT NULL,
			tstamp timestamp DEFAULT (datetime('now'))
		);
		INSERT INTO goose_db_version (version_id, is_applied) VALUES (1, 1);

		CREATE TABLE seeds (
			active bool NOT NULL,
			unit text NOT NULL,
			id text NOT NULL,
			created_at int8 NOT NULL,
			input_fee_ppk int NOT NULL DEFAULT 0,
			version int NOT NULL,
			legacy bool NOT NULL DEFAULT FALSE,
			derivation_path text NOT NULL,
			amounts TEXT NOT NULL,
			final_expiry int8,
			CONSTRAINT seeds_pk PRIMARY KEY (id),
			CONSTRAINT seeds_unique UNIQUE (id)
		);
		CREATE INDEX idx_seed_id ON seeds (id);
		INSERT INTO seeds (active, unit, id, created_at, input_fee_ppk, version, legacy, derivation_path, amounts, final_expiry)
		VALUES (1, 'SAT', 'legacy-seed', 1, 0, 0, 0, '129372''/1967237907''/0''', '[1,2,4]', NULL);
	`)
	if err != nil {
		t.Fatalf("creating legacy schema: %v", err)
	}

	sqlite, err := DatabaseSetup(context.Background(), dir)
	if err != nil {
		t.Fatalf("DatabaseSetup on legacy schema: %v", err)
	}
	defer func() { _ = sqlite.Db.Close() }()

	seeds, err := sqlite.GetAllSeeds()
	if err != nil {
		t.Fatalf("GetAllSeeds(): %v", err)
	}
	if len(seeds) != 1 {
		t.Fatalf("len(seeds) = %d, want 1", len(seeds))
	}
	if seeds[0].AccountID != DefaultAccountID {
		t.Fatalf("seed account_id = %q, want %q", seeds[0].AccountID, DefaultAccountID)
	}
	if seeds[0].DerivationPath != "129372'/1967237907'/0'" {
		t.Fatalf("derivation path changed during compatibility update: %q", seeds[0].DerivationPath)
	}
}

func TestSeedRotationPersistsAccountOwnership(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	sqlite, err := DatabaseSetup(ctx, dir)
	if err != nil {
		t.Fatalf("DatabaseSetup(ctx, dir): %v", err)
	}
	defer func() { _ = sqlite.Db.Close() }()

	tx, err := sqlite.Db.Begin()
	if err != nil {
		t.Fatalf("sqlite.Db.Begin(): %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	secondary := Account{
		Active:     true,
		Id:         "secondary",
		Name:       "secondary",
		Derivation: 11,
		CreatedAt:  2,
	}
	if err := sqlite.CreateAccount(tx, &secondary); err != nil {
		t.Fatalf("CreateAccount(tx, secondary): %v", err)
	}

	seed1 := Seed{Active: true, Version: 1, Id: "id1", Unit: "SAT", AccountID: secondary.Id, InputFeePpk: 1, Legacy: false, Amounts: []uint64{1, 2, 4}, CreatedAt: 2, DerivationPath: "0/0/0"}
	seed2 := Seed{Active: true, Version: 2, Id: "id2", Unit: "SAT", AccountID: secondary.Id, InputFeePpk: 1, Legacy: false, Amounts: []uint64{1, 2, 4}, CreatedAt: 3, DerivationPath: "0/0/1"}

	if err := sqlite.SaveNewSeed(tx, seed1); err != nil {
		t.Fatalf("SaveNewSeed(seed1): %v", err)
	}
	seed1.Active = false
	if err := sqlite.UpdateSeedsActiveStatus(tx, []Seed{seed1}); err != nil {
		t.Fatalf("UpdateSeedsActiveStatus(seed1): %v", err)
	}
	if err := sqlite.SaveNewSeed(tx, seed2); err != nil {
		t.Fatalf("SaveNewSeed(seed2): %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("tx.Commit(): %v", err)
	}

	tx, err = sqlite.Db.Begin()
	if err != nil {
		t.Fatalf("sqlite.Db.Begin() second tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	seeds, err := sqlite.GetSeedsByAccountAndUnit(tx, secondary.Id, cashu.Sat)
	if err != nil {
		t.Fatalf("GetSeedsByAccountAndUnit(): %v", err)
	}
	if len(seeds) != 2 {
		t.Fatalf("len(seeds) = %d, want 2", len(seeds))
	}
	for _, seed := range seeds {
		if seed.AccountID != secondary.Id {
			t.Fatalf("seed %s account_id = %q, want %q", seed.Id, seed.AccountID, secondary.Id)
		}
		if seed.Id == "id1" && seed.Active {
			t.Fatalf("seed id1 should be inactive")
		}
		if seed.Id == "id2" && !seed.Active {
			t.Fatalf("seed id2 should be active")
		}
	}
}

func assertTableExists(t *testing.T, db *sql.DB, table string) {
	t.Helper()
	exists, err := tableExists(context.Background(), db, table)
	if err != nil {
		t.Fatalf("tableExists(%s): %v", table, err)
	}
	if !exists {
		t.Fatalf("table %s does not exist", table)
	}
}

func assertColumnExists(t *testing.T, db *sql.DB, table string, column string) {
	t.Helper()
	exists, err := columnExists(context.Background(), db, table, column)
	if err != nil {
		t.Fatalf("columnExists(%s,%s): %v", table, column, err)
	}
	if !exists {
		t.Fatalf("column %s.%s does not exist", table, column)
	}
}

func assertIndexExists(t *testing.T, db *sql.DB, index string) {
	t.Helper()
	var name string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name = ?`, index).Scan(&name)
	if err != nil {
		t.Fatalf("index %s missing: %v", index, err)
	}
}

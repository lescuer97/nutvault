package database

import (
	// "context"
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log"

	"github.com/lescuer97/nutmix/api/cashu"
	"github.com/pressly/goose/v3"
	_ "github.com/mattn/go-sqlite3"
)

type SqliteDB struct {
	Db *sql.DB
}
//go:embed migrations/*.sql
var embedMigrations embed.FS

func DatabaseSetup(ctx context.Context, databaseDir string) (SqliteDB, error) {
	var sqlitedb SqliteDB

	db, err := sql.Open("sqlite3", databaseDir+"/"+"app.db")
	if err != nil {
		return sqlitedb, fmt.Errorf(`sql.Open("sqlite3", string + "app.db" ). %w`, err)

	}
	goose.SetBaseFS(embedMigrations)

	if err := goose.SetDialect("sqlite3"); err != nil {
		log.Fatalf("Error setting dialect: %v", err)
	}

	if err := goose.Up(db, "migrations"); err != nil {
		log.Fatalf("Error running migrations: %v", err)
	}
	db.SetMaxOpenConns(1)

	sqlitedb.Db = db

	return sqlitedb, nil
}

func (sq *SqliteDB) GetAllSeeds( ) ([]cashu.Seed, error) {
        seeds := []cashu.Seed{}
	stmt, err := sq.Db.Prepare(`SELECT  created_at, active, version, unit, id,  "input_fee_ppk" FROM seeds ORDER BY version DESC`)
	if err != nil {
		return seeds, fmt.Errorf(`SELECT  created_at, active, version, unit, id,  "input_fee_ppk" FROM seeds ORDER BY version DESC %w`, err)
	}
	defer stmt.Close()

	rows, err := stmt.Query()
	if err != nil {
		return seeds, fmt.Errorf(`stmt.Query(args...). %w`, err)
	}
	defer rows.Close()

	for rows.Next() {
		var seed cashu.Seed
		err = rows.Scan(&seed.CreatedAt, &seed.Active, &seed.Version, &seed.Unit, &seed.Id, &seed.InputFeePpk)
		if err != nil {
			return seeds, fmt.Errorf(`rows.Scan(&seed.CreatedAt, &seed.Active, &seed.Version, &seed.Unit, &seed.Id, &seed.InputFeePpk) %w`, err)
		}

		seeds = append(seeds, seed)
	}
        return seeds, nil
}

func (sq *SqliteDB) GetSeedsByUnit(tx *sql.Tx, unit cashu.Unit) ([]cashu.Seed, error) {
        seeds := []cashu.Seed{}
	stmt, err := tx.Prepare("SELECT  created_at, active, version, unit, id, input_fee_ppk FROM seeds WHERE unit = $1")
	if err != nil {
		return seeds, fmt.Errorf(`tx.Prepare("SELECT  created_at, active, version, unit, id, input_fee_ppk FROM seeds WHERE unit = $1"). %w`, err)
	}
	defer stmt.Close()

	rows, err := stmt.Query(unit.String())
	if err != nil {
		return seeds, fmt.Errorf(`stmt.Query(args...). %w`, err)
	}
	defer rows.Close()

	for rows.Next() {
		var seed cashu.Seed
		err = rows.Scan(&seed.CreatedAt, &seed.Active, &seed.Version, &seed.Unit, &seed.Id, &seed.InputFeePpk)
		if err != nil {
			return seeds, fmt.Errorf(`rows.Scan(&seed.CreatedAt, &seed.Active, &seed.Version, &seed.Unit, &seed.Id, &seed.InputFeePpk) %w`, err)
		}

		seeds = append(seeds, seed)
	}
        return seeds, nil
}
func (sq *SqliteDB) SaveNewSeed(tx *sql.Tx, seed cashu.Seed) error {

	tries := 0
	for {
		tries += 1
		_, err := tx.Exec("INSERT INTO seeds ( active, created_at, unit, id, version, input_fee_ppk) VALUES ($1, $2, $3, $4, $5, $6)", seed.Active, seed.CreatedAt, seed.Unit, seed.Id, seed.Version, seed.InputFeePpk)

		switch {
		case err != nil && tries < 3:
			continue
		case err != nil && tries >= 3:
			return fmt.Errorf("INSERT INTO seeds ( active, created_at, unit, id, version, input_fee_ppk) VALUES ($1, $2, $3, $4, $5, $6): %w", err)
		case err == nil:
			return nil
		}

	}
}

func (sq *SqliteDB) UpdateSeedsActiveStatus(tx *sql.Tx, seeds []cashu.Seed) error {
    stmt, err := tx.Prepare("UPDATE seeds SET active = ? WHERE id = ?")
    if err != nil {
        return fmt.Errorf(`UPDATE seeds SET active = ? WHERE id = ?: %w`, err)
    }
    defer stmt.Close()

    for _, seed := range seeds {
        _, err := stmt.Exec(seed.Active, seed.Id)
        if err != nil {
            return fmt.Errorf("stmt.Exec(seed.Active, seed.ID): %w", err)
        }
    }
    
    return nil

}

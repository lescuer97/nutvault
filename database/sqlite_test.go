package database

import (
	"context"
	"log"
	"testing"

	"github.com/lescuer97/nutmix/api/cashu"
)

func TestSeedRotation(t *testing.T) {

	dir := t.TempDir()
	ctx := context.Background()

	sqlite, err := DatabaseSetup(ctx, dir)
	defer sqlite.Db.Close()
	if err != nil {
		t.Fatalf(`database.DatabaseSetup(ctx, "migrations"). %+v`, err)
	}

	seed := Seed{
		Active:      true,
		Version:     1,
		Id:          "id1",
		Unit:        cashu.Sat.String(),
		InputFeePpk: 1,
		Legacy:      false,
		Amounts:     []uint64{1, 2, 4},
		CreatedAt:   2,
	}

	tx, err := sqlite.Db.Begin()
	if err != nil {
		t.Fatalf(`sqlite.Db.Begin(). %+v`, err)
	}
	defer tx.Rollback()

	err = sqlite.SaveNewSeed(tx, seed)
	if err != nil {
		t.Errorf(`Could not save seed. %+v`, err)
	}

	seed.Active = false
	err = sqlite.UpdateSeedsActiveStatus(tx, []Seed{seed})
	if err != nil {
		t.Errorf(`Could not save seed. %+v`, err)
	}

	seed2 := Seed{
		Active:      true,
		Version:     2,
		Id:          "id2",
		Unit:        cashu.Sat.String(),
		InputFeePpk: 1,
		Legacy:      false,
		Amounts:     []uint64{1, 2, 4},
		CreatedAt:   2,
	}

	log.Printf("Before Save New seed")
	err = sqlite.SaveNewSeed(tx, seed2)
	if err != nil {
		t.Errorf(`Could not save seed. %+v`, err)
	}

	err = tx.Commit()
	if err != nil {
		t.Fatalf(`Could not commit transaction. %+v`, err)
	}
	seeds, err := sqlite.GetAllSeeds()
	if err != nil {
		t.Errorf(`sqlite.GetAllSeeds(). %+v`, err)
	}

	for _, seed := range seeds {
		if seed.Id == "id1" && seed.Active != false {
			t.Error(`seed with id: id1 should be inactive`)
		}
		if seed.Id == "id2" && seed.Active != true {
			t.Error(`seed with id: id2 should be inactive`)
		}
	}

}
func TestSeedRotation2(t *testing.T) {

	dir := t.TempDir()
	ctx := context.Background()

	sqlite, err := DatabaseSetup(ctx, dir)
	defer sqlite.Db.Close()
	if err != nil {
		t.Fatalf(`database.DatabaseSetup(ctx, "migrations"). %+v`, err)
	}

	seeds, err := sqlite.GetAllSeeds()
	if err != nil {
		t.Errorf(`sqlite.GetAllSeeds(). %+v`, err)
	}

	seed := Seed{
		Active:      true,
		Version:     1,
		Id:          "id1",
		Unit:        cashu.Sat.String(),
		InputFeePpk: 1,
		Legacy:      false,
		Amounts:     []uint64{1, 2, 4},
		CreatedAt:   2,
	}

	tx, err := sqlite.Db.Begin()
	if err != nil {
		t.Fatalf(`sqlite.Db.Begin(). %+v`, err)
	}
	defer tx.Rollback()

	err = sqlite.SaveNewSeed(tx, seed)
	if err != nil {
		t.Errorf(`Could not save seed. %+v`, err)
	}

	err = tx.Commit()
	if err != nil {
		t.Fatalf(`Could not commit transaction. %+v`, err)
	}

	seeds, err = sqlite.GetAllSeeds()
	if err != nil {
		t.Errorf(`sqlite.GetAllSeeds(). %+v`, err)
	}
	for _, seed := range seeds {
		if seed.Id == "id1" && seed.Active != true {
			t.Error(`seed with id: id1 should be inactive`)
		}
	}

}

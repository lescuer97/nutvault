package database

import (
	"context"
	"log"
	"testing"

	"github.com/lescuer97/nutmix/api/cashu"
)

func TestSeedRotation(t *testing.T) {

	log.Printf("before tempdir setup")
	dir := t.TempDir()
	ctx := context.Background()

	log.Printf("before database setup")
	sqlite, err := DatabaseSetup(ctx, dir)
	defer sqlite.Db.Close()
	if err != nil {
		t.Fatalf(`database.DatabaseSetup(ctx, "migrations"). %+v`, err)
	}
	log.Printf("after database setup")

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
	log.Printf("Before tx")
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
	log.Printf("before get all seeds")
	seeds, err := sqlite.GetAllSeeds()
	if err != nil {
		t.Errorf(`sqlite.GetAllSeeds(). %+v`, err)
	}
	log.Printf("after Seeds %+v", seeds)

	for _, seed := range seeds {
		if seed.Id == "id1" && seed.Active != false {
			t.Error(`seed with id: id1 should be inactive`)
		}
		if seed.Id == "id2" && seed.Active != true {
			t.Error(`seed with id: id2 should be inactive`)
		}
	}

	log.Printf("before commit")

	log.Printf("After commit")

}

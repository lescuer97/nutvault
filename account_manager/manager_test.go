package accountmanager

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"nutmix_remote_signer/database"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lescuer97/nutmix/api/cashu"
)

func TestCreateAccount(t *testing.T) {
	sqlite, err := database.DatabaseSetup(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("database.DatabaseSetup(...): %v", err)
	}
	defer func() { _ = sqlite.Db.Close() }()

	manager := NewManager(&sqlite, nil)
	pubkey, _ := btcec.PrivKeyFromBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})
	account, err := manager.CreateAccount(context.Background(), pubkey.PubKey(), "client-fingerprint")
	if err != nil {
		t.Fatalf("manager.CreateAccount(...): %v", err)
	}
	if account.ClientPubkeyFP != "client-fingerprint" {
		t.Fatalf("ClientPubkeyFP = %q, want %q", account.ClientPubkeyFP, "client-fingerprint")
	}
	if account.Id == "" {
		t.Fatalf("account id should not be empty")
	}

	expected := sha256.Sum256(append(pubkey.PubKey().SerializeCompressed(), mustHexDecode(t, account.Id)...))
	if account.Derivation != binary.LittleEndian.Uint32(expected[:4]) {
		t.Fatalf("derivation = %d, want %d", account.Derivation, binary.LittleEndian.Uint32(expected[:4]))
	}

	stored, err := sqlite.GetAccountByID(account.Id)
	if err != nil {
		t.Fatalf("sqlite.GetAccountByID(account.Id): %v", err)
	}
	if stored.ClientPubkeyFP != account.ClientPubkeyFP {
		t.Fatalf("stored.ClientPubkeyFP = %q, want %q", stored.ClientPubkeyFP, account.ClientPubkeyFP)
	}
}

func TestUpdateKeyName(t *testing.T) {
	sqlite, manager, account := setupManagerTestAccount(t)
	defer func() { _ = sqlite.Db.Close() }()

	if err := manager.UpdateKeyName(context.Background(), account.Id, "new name"); err != nil {
		t.Fatalf("manager.UpdateKeyName(...): %v", err)
	}

	stored, err := sqlite.GetAccountByID(account.Id)
	if err != nil {
		t.Fatalf("sqlite.GetAccountByID(...): %v", err)
	}
	if stored.Name != "new name" {
		t.Fatalf("stored.Name = %q, want %q", stored.Name, "new name")
	}
}

func TestGetKeysFromNpub(t *testing.T) {
	sqlite, err := database.DatabaseSetup(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("database.DatabaseSetup(...): %v", err)
	}
	defer func() { _ = sqlite.Db.Close() }()

	manager := NewManager(&sqlite, nil)
	privA, _ := btcec.PrivKeyFromBytes([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	privB, _ := btcec.PrivKeyFromBytes([]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2})

	if _, err := manager.CreateAccount(context.Background(), privA.PubKey(), "fp-a"); err != nil {
		t.Fatalf("CreateAccount(privA): %v", err)
	}
	if _, err := manager.CreateAccount(context.Background(), privB.PubKey(), "fp-b"); err != nil {
		t.Fatalf("CreateAccount(privB): %v", err)
	}

	accounts, err := manager.GetKeysFromNpub(privA.PubKey())
	if err != nil {
		t.Fatalf("manager.GetKeysFromNpub(privA.PubKey()): %v", err)
	}
	if len(accounts) != 1 {
		t.Fatalf("len(accounts) = %d, want 1", len(accounts))
	}
}

func TestGetKeysetsForAccount(t *testing.T) {
	sqlite, manager, account := setupManagerTestAccount(t)
	defer func() { _ = sqlite.Db.Close() }()

	tx, err := sqlite.Db.Begin()
	if err != nil {
		t.Fatalf("sqlite.Db.Begin(): %v", err)
	}
	other := database.Account{Active: true, Id: "other", Name: "other", Derivation: 21, CreatedAt: 1}
	if err := sqlite.CreateAccount(tx, &other); err != nil {
		t.Fatalf("sqlite.CreateAccount(tx, &other): %v", err)
	}
	seedA := database.Seed{Active: true, Version: 1, Id: "seed-a", Unit: "SAT", AccountID: account.Id, Amounts: []uint64{1, 2}, CreatedAt: 1, DerivationPath: "0/0/0"}
	seedB := database.Seed{Active: true, Version: 1, Id: "seed-b", Unit: "SAT", AccountID: other.Id, Amounts: []uint64{1}, CreatedAt: 1, DerivationPath: "0/0/1"}
	if err := sqlite.SaveNewSeed(tx, seedA); err != nil {
		t.Fatalf("sqlite.SaveNewSeed(tx, seedA): %v", err)
	}
	if err := sqlite.SaveNewSeed(tx, seedB); err != nil {
		t.Fatalf("sqlite.SaveNewSeed(tx, seedB): %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("tx.Commit(): %v", err)
	}

	seeds, err := manager.GetKeysetsForAccount(context.Background(), account.Id)
	if err != nil {
		t.Fatalf("manager.GetKeysetsForAccount(...): %v", err)
	}
	if len(seeds) != 1 {
		t.Fatalf("len(seeds) = %d, want 1", len(seeds))
	}
	if seeds[0].AccountID != account.Id {
		t.Fatalf("seed account = %q, want %q", seeds[0].AccountID, account.Id)
	}
}

func TestSetKeyActive(t *testing.T) {
	sqlite, manager, account := setupManagerTestAccount(t)
	defer func() { _ = sqlite.Db.Close() }()

	if err := manager.SetKeyActive(context.Background(), account.Id, false); err != nil {
		t.Fatalf("manager.SetKeyActive(...): %v", err)
	}
	active, err := manager.GetKeyActive(context.Background(), account.Id)
	if err != nil {
		t.Fatalf("manager.GetKeyActive(...): %v", err)
	}
	if active {
		t.Fatalf("account should be inactive")
	}
}

func TestAccountOwnershipCheck(t *testing.T) {
	sqlite, manager, account := setupManagerTestAccount(t)
	defer func() { _ = sqlite.Db.Close() }()

	owner, err := manager.AccountBelongsToPubkey(context.Background(), account.Id, account.Npub)
	if err != nil {
		t.Fatalf("manager.AccountBelongsToPubkey(owner): %v", err)
	}
	if owner.Id != account.Id {
		t.Fatalf("owner.Id = %q, want %q", owner.Id, account.Id)
	}

	otherPriv, _ := btcec.PrivKeyFromBytes([]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9})
	_, err = manager.AccountBelongsToPubkey(context.Background(), account.Id, otherPriv.PubKey())
	if err == nil {
		t.Fatalf("expected ownership check to fail")
	}
}

func setupManagerTestAccount(t *testing.T) (database.SqliteDB, Manager, *database.Account) {
	t.Helper()
	sqlite, err := database.DatabaseSetup(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("database.DatabaseSetup(...): %v", err)
	}
	manager := NewManager(&sqlite, nil)
	priv, _ := btcec.PrivKeyFromBytes([]byte{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34})
	account, err := manager.CreateAccount(context.Background(), priv.PubKey(), "fingerprint")
	if err != nil {
		t.Fatalf("manager.CreateAccount(...): %v", err)
	}
	return sqlite, manager, account
}

func mustHexDecode(t *testing.T, hexString string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(hexString)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", hexString, err)
	}
	return decoded
}

func TestAccountOwnershipCheckMissing(t *testing.T) {
	sqlite, err := database.DatabaseSetup(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("database.DatabaseSetup(...): %v", err)
	}
	defer func() { _ = sqlite.Db.Close() }()
	manager := NewManager(&sqlite, nil)
	priv, _ := btcec.PrivKeyFromBytes([]byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5})
	_, err = manager.AccountBelongsToPubkey(context.Background(), "missing", priv.PubKey())
	if err == nil || err == sql.ErrNoRows {
		if err == nil {
			t.Fatalf("expected missing account error")
		}
	}
}

func TestGetKeysetsForAccountEmpty(t *testing.T) {
	sqlite, manager, account := setupManagerTestAccount(t)
	defer func() { _ = sqlite.Db.Close() }()
	seeds, err := manager.GetKeysetsForAccount(context.Background(), account.Id)
	if err != nil {
		t.Fatalf("manager.GetKeysetsForAccount(...): %v", err)
	}
	if len(seeds) != 0 {
		t.Fatalf("len(seeds) = %d, want 0", len(seeds))
	}
}

func TestGetKeysetsForAccountUsesStoredUnit(t *testing.T) {
	sqlite, manager, account := setupManagerTestAccount(t)
	defer func() { _ = sqlite.Db.Close() }()
	tx, err := sqlite.Db.Begin()
	if err != nil {
		t.Fatalf("sqlite.Db.Begin(): %v", err)
	}
	seed := database.Seed{Active: true, Version: 1, Id: "seed-c", Unit: cashu.AUTH.String(), AccountID: account.Id, Amounts: []uint64{1}, CreatedAt: 1, DerivationPath: "0/0/2"}
	if err := sqlite.SaveNewSeed(tx, seed); err != nil {
		t.Fatalf("sqlite.SaveNewSeed(tx, seed): %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("tx.Commit(): %v", err)
	}
	seeds, err := manager.GetKeysetsForAccount(context.Background(), account.Id)
	if err != nil {
		t.Fatalf("manager.GetKeysetsForAccount(...): %v", err)
	}
	if len(seeds) != 1 || seeds[0].Unit != cashu.AUTH.String() {
		t.Fatalf("unexpected seeds returned: %+v", seeds)
	}
}

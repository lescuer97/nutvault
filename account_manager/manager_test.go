package accountmanager

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"nutmix_remote_signer/database"

	"github.com/btcsuite/btcd/btcec/v2"
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

func mustHexDecode(t *testing.T, hexString string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(hexString)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", hexString, err)
	}
	return decoded
}

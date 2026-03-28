package signer

import (
	"encoding/hex"
	"testing"
	"time"

	"nutmix_remote_signer/database"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lescuer97/bip85"
	"github.com/lescuer97/nutmix/api/cashu"
)

func TestDifferentAccountsProduceDifferentKeysets(t *testing.T) {
	bip85Key, err := bip85.NewBip85FromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "")
	if err != nil {
		t.Fatalf("bip85.NewBip85FromMnemonic(...): %v", err)
	}
	accountA, err := getDerivedAccountKey(bip85Key, 1)
	if err != nil {
		t.Fatalf("getDerivedAccountKey(..., 1): %v", err)
	}
	accountB, err := getDerivedAccountKey(bip85Key, 2)
	if err != nil {
		t.Fatalf("getDerivedAccountKey(..., 2): %v", err)
	}

	seed := database.Seed{
		Active:         true,
		CreatedAt:      time.Now().Unix(),
		Version:        1,
		Unit:           cashu.Sat.String(),
		InputFeePpk:    0,
		Legacy:         false,
		Amounts:        []uint64{1, 2, 4, 8},
		DerivationPath: keyDerivation(1, cashu.Sat),
	}

	keysetA, err := DeriveKeyset(accountA, seed)
	if err != nil {
		t.Fatalf("DeriveKeyset(accountA, seed): %v", err)
	}
	keysetB, err := DeriveKeyset(accountB, seed)
	if err != nil {
		t.Fatalf("DeriveKeyset(accountB, seed): %v", err)
	}

	if hex.EncodeToString(keysetA.Id) == hex.EncodeToString(keysetB.Id) {
		t.Fatalf("different account roots produced the same keyset id")
	}
	if hex.EncodeToString(keysetA.Keys[1].PublicKey.SerializeCompressed()) == hex.EncodeToString(keysetB.Keys[1].PublicKey.SerializeCompressed()) {
		t.Fatalf("different account roots produced the same public key")
	}
}

func TestDefaultAccountKeepsExistingKeysetVector(t *testing.T) {
	privateKeyBytes, err := hex.DecodeString(MintPrivateKey)
	if err != nil {
		t.Fatalf("hex.DecodeString(MintPrivateKey): %v", err)
	}
	masterKey, err := hdkeychain.NewMaster(privateKeyBytes, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("hdkeychain.NewMaster(...): %v", err)
	}
	seed := database.Seed{
		Active:         true,
		CreatedAt:      time.Now().Unix(),
		Version:        1,
		Unit:           cashu.Sat.String(),
		InputFeePpk:    0,
		Legacy:         false,
		Amounts:        GetAmountsFromMaxOrder(DefaultMaxOrder),
		DerivationPath: keyDerivation(1, cashu.Sat),
	}
	keyset, err := DeriveKeyset(masterKey, seed)
	if err != nil {
		t.Fatalf("DeriveKeyset(masterKey, seed): %v", err)
	}
	if hex.EncodeToString(keyset.Id) != "0107b4645ae16ff212d20e93a50ce58fbf98f39cdc74e5de0c10d53d308b83e7f5" {
		t.Fatalf("default account keyset id changed: %x", keyset.Id)
	}
}

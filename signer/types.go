package signer

import (
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"time"

	"github.com/elnosh/gonuts/crypto"
)

type MintPublicKeyset struct {
	Id                []byte
	Unit              string
	Keys              map[uint64][]byte
	FinalExpiry       *time.Time
	Amounts           []uint64
	Version           uint64
	InputFeePpk       uint
	DerivationPathIdx uint32
	Active            bool
	Legacy            bool
}
type MintKeyset struct {
	Id                []byte
	Unit              string
	Keys              map[uint64]crypto.KeyPair
	FinalExpiry       *time.Time
	Amounts           []uint64
	Version           uint64
	InputFeePpk       uint
	DerivationPathIdx uint32
	Active            bool
}

func MakeMintPublickeys(mintKey MintKeyset) MintPublicKeyset {
	result := MintPublicKeyset{
		Id:                mintKey.Id,
		Unit:              mintKey.Unit,
		Active:            mintKey.Active,
		DerivationPathIdx: mintKey.DerivationPathIdx,
		Keys:              make(map[uint64][]byte, len(mintKey.Keys)),
		InputFeePpk:       mintKey.InputFeePpk,
		Version:           mintKey.Version,
		FinalExpiry:       mintKey.FinalExpiry,
		Amounts:           mintKey.Amounts,
		Legacy:            false,
	}

	for key, keypair := range mintKey.Keys {
		result.Keys[key] = keypair.PublicKey.SerializeCompressed()
	}

	if len(mintKey.Keys) != len(result.Keys) {
		log.Panicf("Result Keys and mintKey.Keys should be of the same length")
	}

	return result
}

func (s *Signer) GenerateMintKeysFromPublicKeysets(keysetIndex KeysetGenerationIndexes) (map[string]MintKeyset, error) {

	privateKeysets := make(map[string]MintKeyset)
	masterKey, err := GetMasterKey()
	defer func() {
		masterKey = nil
	}()
	if err != nil {
		return nil, fmt.Errorf(" bip32.NewMasterKey(privateKey.Serialize()). %w", err)
	}

	slog.Debug(fmt.Sprintf("\n generating keys for %v keysets\n ", len(keysetIndex)))
	keysetsMap := s.store.GetKeysetsMapCopy()
	for i, val := range keysetsMap {
		keysetAmounts, exists := keysetIndex[hex.EncodeToString(val.Id)]
		if !exists {
			continue
		}

		hexId := hex.EncodeToString(val.Id)
		privateKeysets[i] = MintKeyset{Id: val.Id, Unit: val.Unit, DerivationPathIdx: val.DerivationPathIdx, Active: val.Active, InputFeePpk: val.InputFeePpk, FinalExpiry: val.FinalExpiry, Amounts: nil, Version: 0, Keys: nil}
		keyset := MintKeyset{Id: val.Id, Unit: val.Unit, DerivationPathIdx: val.DerivationPathIdx, Active: val.Active, InputFeePpk: val.InputFeePpk, Keys: make(map[uint64]crypto.KeyPair), FinalExpiry: val.FinalExpiry, Amounts: nil, Version: 0}

		keys, err := KeyDerivation(masterKey, val.DerivationPathIdx, val.Unit, keysetAmounts)
		if err != nil {
			return privateKeysets, fmt.Errorf("KeyDerivation(mintKey,&keyset, seed, unit) %w", err)
		}
		keyset.Keys = keys
		privateKeysets[hexId] = keyset
	}
	return privateKeysets, nil
}

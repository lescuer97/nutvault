package signer

import (
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"nutmix_remote_signer/database"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/elnosh/gonuts/crypto"
	"github.com/lescuer97/nutmix/api/cashu"
)

type MintPublicKeyset struct {
	Id                []byte
	Unit              string
	Active            bool
	DerivationPathIdx uint32
	Keys              map[uint64][]byte
	InputFeePpk       uint
	Legacy            bool
}
type MintKeyset struct {
	Id                []byte
	Unit              string
	Active            bool
	DerivationPathIdx uint32
	Keys              map[uint64]crypto.KeyPair
	InputFeePpk       uint
}

func MakeMintPublickeys(mintKey MintKeyset) MintPublicKeyset {
	result := MintPublicKeyset{
		Id:                mintKey.Id,
		Unit:              mintKey.Unit,
		Active:            mintKey.Active,
		DerivationPathIdx: mintKey.DerivationPathIdx,
		Keys:              make(map[uint64][]byte, len(mintKey.Keys)),
		InputFeePpk:       uint(mintKey.InputFeePpk),
	}

	for key, keypair := range mintKey.Keys {
		result.Keys[key] = keypair.PublicKey.SerializeCompressed()
	}

	if len(mintKey.Keys) != len(result.Keys) {
		log.Panicf("Result Keys and mintKey.Keys should be of the same length")
	}

	return result
}

func (s *Signer) GenerateMintKeysFromPublicKeysets(keysetIndex KeysetGenerationIndexes, accountId string) (map[string]MintKeyset, error) {

	privateKeysets := make(map[string]MintKeyset)
	seedFromDBUS, err := GetNutmixSignerKey()
	defer func() {
		seedFromDBUS = ""
	}()
	if err != nil {
		return privateKeysets, fmt.Errorf("signer.getSignerPrivateKey(). %w", err)
	}

	privateKey, err := s.getSignerPrivateKey(seedFromDBUS)
	defer func() {
		privateKey = nil
	}()
	if err != nil {
		return privateKeysets, fmt.Errorf("signer.getSignerPrivateKey(). %w", err)
	}
	mintKey, err := hdkeychain.NewMaster(privateKey.Serialize(), &chaincfg.MainNetParams)
	defer func() {
		mintKey = nil
	}()

	if err != nil {
		return privateKeysets, fmt.Errorf(" bip32.NewMasterKey(privateKey.Serialize()). %w", err)
	}

	slog.Debug(fmt.Sprintf("\n generating keys for %v keysets\n ", len(keysetIndex)))
	signer, exists := s.signers[accountId]
	if !exists {
		return privateKeysets, fmt.Errorf("signer account does not exists. %w", err)
	}
	for i, val := range signer.keysets {

		keysetAmounts, exists := keysetIndex[hex.EncodeToString(val.Id)]
		if !exists {
			return privateKeysets, fmt.Errorf("Could not find keyset form index. Id: %v. %w", val.Id, cashu.ErrKeysetNotFound)
		}

		hexId := hex.EncodeToString(val.Id)
		privateKeysets[i] = MintKeyset{Id: val.Id, Unit: val.Unit, DerivationPathIdx: val.DerivationPathIdx, Active: val.Active, InputFeePpk: val.InputFeePpk}
		keyset := MintKeyset{Id: val.Id, Unit: val.Unit, DerivationPathIdx: val.DerivationPathIdx, Active: val.Active, InputFeePpk: val.InputFeePpk, Keys: make(map[uint64]crypto.KeyPair)}

		unit, err := cashu.UnitFromString(val.Unit)
		if err != nil {
			return privateKeysets, fmt.Errorf("cashu.UnitFromString(val.Unit). %w", err)
		}

		seed := database.Seed{Active: val.Active, Id: hexId, Unit: val.Unit, Version: int(val.DerivationPathIdx), InputFeePpk: val.InputFeePpk, Legacy: val.Legacy, AccountId: accountId}
		if val.Legacy {
			err := LegacyKeyDerivation(mintKey, &keyset, seed, unit, keysetAmounts)
			if err != nil {
				return privateKeysets, fmt.Errorf("LegacyKeyDerivation(mintKey,&keyset, seed, unit ) %w", err)
			}
		} else {
			err := KeyDerivation(mintKey, &keyset, seed, unit, keysetAmounts)
			if err != nil {
				return privateKeysets, fmt.Errorf("KeyDerivation(mintKey,&keyset, seed, unit) %w", err)
			}
		}
		privateKeysets[hexId] = keyset
	}
	return privateKeysets, nil
}

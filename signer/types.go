package signer

import (
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
	Id                string
	Unit              string
	Active            bool
	DerivationPathIdx uint32
	Keys              map[uint64][]byte
	InputFeePpk       uint
	Legacy            bool
}

func MakeMintPublickeys(mintKey crypto.MintKeyset) MintPublicKeyset {
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

func (s *Signer) GenerateMintKeysFromPublicKeysets(amounts keysetAmounts) (map[string]crypto.MintKeyset, error) {

	privateKeysets := make(map[string]crypto.MintKeyset)
	privateKeyFromDbus, err := GetNutmixSignerKey("")
	defer func() {
		privateKeyFromDbus = ""
	}()
	if err != nil {
		return privateKeysets, fmt.Errorf("signer.getSignerPrivateKey(). %w", err)
	}

	privateKey, err := s.getSignerPrivateKey(privateKeyFromDbus)
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

	slog.Debug(fmt.Sprintf("\n generating keys for %v amounts\n ", len(amounts)))
	for i, val := range s.keysets {

		privateKeysets[i] = crypto.MintKeyset{Id: val.Id, Unit: val.Id, DerivationPathIdx: val.DerivationPathIdx, Active: val.Active, InputFeePpk: val.InputFeePpk}
		keyset := crypto.MintKeyset{Id: val.Id, Unit: val.Id, DerivationPathIdx: val.DerivationPathIdx, Active: val.Active, InputFeePpk: val.InputFeePpk, Keys: make(map[uint64]crypto.KeyPair)}

		unit, err := cashu.UnitFromString(val.Unit)
		if err != nil {
			return privateKeysets, fmt.Errorf("cashu.UnitFromString(val.Unit). %w", err)
		}

		seed := database.Seed{Active: val.Active, Id: val.Id, Version: int(val.DerivationPathIdx), InputFeePpk: val.InputFeePpk, Legacy: val.Legacy}

		if val.Legacy {
			err := LegacyKeyDerivation(mintKey, &keyset, seed, unit, amounts)
			if err != nil {
				return privateKeysets, fmt.Errorf("LegacyKeyDerivation(mintKey,&keyset, seed, unit ) %w", err)
			}
		} else {
			err := KeyDerivation(mintKey, &keyset, seed, unit, amounts)
			if err != nil {
				return privateKeysets, fmt.Errorf("KeyDerivation(mintKey,&keyset, seed, unit) %w", err)
			}
		}
		privateKeysets[val.Id] = keyset
	}
	return privateKeysets, nil
}

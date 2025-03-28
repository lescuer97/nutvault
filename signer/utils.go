package signer

import (
	"fmt"
	"nutmix_remote_signer/database"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/elnosh/gonuts/cashu/nuts/nut01"
	"github.com/elnosh/gonuts/crypto"
	"github.com/lescuer97/nutmix/api/cashu"
)

func OrderKeysetByUnit(keysets []crypto.MintKeyset) nut01.GetKeysResponse {
	// keysets[0].
	var typesOfUnits = make(map[string][]crypto.MintKeyset)

	for _, keyset := range keysets {
		if len(typesOfUnits[keyset.Unit]) == 0 {
			typesOfUnits[keyset.Unit] = append(typesOfUnits[keyset.Unit], keyset)
			continue
		} else {
			typesOfUnits[keyset.Unit] = append(typesOfUnits[keyset.Unit], keyset)
		}
	}

	res := nut01.GetKeysResponse{}

	res.Keysets = []nut01.Keyset{}

	for _, unitKeysets := range typesOfUnits {
		for _, mintKey := range unitKeysets {

			keyset := nut01.Keyset{}
			keyset.Id = mintKey.Id
			keyset.Unit = mintKey.Unit
			keyset.Keys = mintKey.DerivePublic()
			res.Keysets = append(res.Keysets, keyset)
		}
	}
	return res

}
func DeriveKeyset(mintKey *hdkeychain.ExtendedKey, seed database.Seed) (crypto.MintKeyset, error) {
	keyset := crypto.MintKeyset{
		Unit:              seed.Unit,
		InputFeePpk:       seed.InputFeePpk,
		Active:            seed.Active,
		DerivationPathIdx: uint32(seed.Version),
		Keys:              make(map[uint64]crypto.KeyPair),
	}
	// var keypair crypto.KeyPair
	unit, err := cashu.UnitFromString(seed.Unit)
	if err != nil {
		return keyset, fmt.Errorf("UnitFromString(seed.Unit) %w", err)
	}

	if seed.Legacy {
		err := LegacyKeyDerivation(mintKey, &keyset, seed, unit)
		if err != nil {
			return keyset, fmt.Errorf("LegacyKeyDerivation(mintKey,&keyset, seed, unit ) %w", err)
		}
	} else {
		err := KeyDerivation(mintKey, &keyset, seed, unit)
		if err != nil {
			return keyset, fmt.Errorf("KeyDerivation(mintKey,&keyset, seed, unit) %w", err)
		}

	}

	publicKeys := make(map[uint64]*secp256k1.PublicKey)
	for i, val := range keyset.Keys {
		publicKeys[i] = val.PublicKey
	}
	id := crypto.DeriveKeysetId(publicKeys)

	keyset.Id = id

	return keyset, nil
}

func LegacyKeyDerivation(key *hdkeychain.ExtendedKey, keyset *crypto.MintKeyset, seed database.Seed, unit cashu.Unit) error {
	unitKey, err := key.Derive(uint32(unit.EnumIndex()))

	if err != nil {
		return fmt.Errorf("mintKey.NewChildKey(uint32(unit.EnumIndex())). %w", err)
	}

	versionKey, err := unitKey.Derive(uint32(seed.Version))
	if err != nil {
		return fmt.Errorf("mintKey.NewChildKey(uint32(seed.Version)) %w", err)
	}

	amounts := cashu.GetAmountsForKeysets()

	if unit == cashu.AUTH {
		amounts = []uint64{amounts[0]}
	}

	err = GenerateKeypairsLegacy(versionKey, amounts, keyset)
	if err != nil {
		return fmt.Errorf(`GenerateKeypairs(versionKey, values, &keyset) %w`, err)
	}
	return nil
}

func KeyDerivation(key *hdkeychain.ExtendedKey, keyset *crypto.MintKeyset, seed database.Seed, unit cashu.Unit) error {
	unitKey, err := key.Derive(hdkeychain.HardenedKeyStart + uint32(unit.EnumIndex()))

	if err != nil {
		return fmt.Errorf("mintKey.NewChildKey(uint32(unit.EnumIndex())). %w", err)
	}

	versionKey, err := unitKey.Derive(hdkeychain.HardenedKeyStart + uint32(seed.Version))
	if err != nil {
		return fmt.Errorf("mintKey.NewChildKey(uint32(seed.Version)) %w", err)
	}

	amounts := cashu.GetAmountsForKeysets()

	if unit == cashu.AUTH {
		amounts = []uint64{amounts[0]}
	}

	err = GenerateKeypairs(versionKey, amounts, keyset)
	if err != nil {
		return fmt.Errorf(`GenerateKeypairs(versionKey, values, &keyset) %w`, err)
	}
	return nil
}

func GenerateKeypairsLegacy(versionKey *hdkeychain.ExtendedKey, values []uint64, keyset *crypto.MintKeyset) error {
	for i, value := range values {
		// uses the value it represents to derive the key
		childKey, err := versionKey.Derive(uint32(i))
		if err != nil {
			return err
		}
		privKey, err := childKey.ECPrivKey()
		if err != nil {
			return err
		}
		// privKey := secp256k1.PrivKeyFromBytes(childKey.Key)
		keypair := crypto.KeyPair{
			PrivateKey: privKey,
			PublicKey:  privKey.PubKey(),
		}
		keyset.Keys[value] = keypair
	}
	return nil
}

func GenerateKeypairs(versionKey *hdkeychain.ExtendedKey, values []uint64, keyset *crypto.MintKeyset) error {
	for i, value := range values {
		// uses the value it represents to derive the key
		childKey, err := versionKey.Derive(hdkeychain.HardenedKeyStart + uint32(i))
		if err != nil {
			return err
		}
		privKey, err := childKey.ECPrivKey()
		if err != nil {
			return err
		}
		keypair := crypto.KeyPair{
			PrivateKey: privKey,
			PublicKey:  privKey.PubKey(),
		}
		keyset.Keys[value] = keypair
	}
	return nil
}

func GetKeysetsFromSeeds(seeds []database.Seed, mintKey *hdkeychain.ExtendedKey) (map[string]crypto.MintKeyset, map[string]crypto.MintKeyset, error) {
	newKeysets := make(map[string]crypto.MintKeyset)
	newActiveKeysets := make(map[string]crypto.MintKeyset)

	for _, seed := range seeds {
		keyset, err := DeriveKeyset(mintKey, seed)
		if err != nil {
			return newKeysets, newActiveKeysets, fmt.Errorf("DeriveKeyset(mintKey, seed) %w", err)
		}

		if keyset.Id != seed.Id {
			panic("The ids should be same")
		}

		if seed.Active {
			newActiveKeysets[seed.Id] = keyset
		}

		newKeysets[seed.Id] = keyset
	}
	return newKeysets, newActiveKeysets, nil

}

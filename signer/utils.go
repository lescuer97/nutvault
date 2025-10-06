package signer

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"math"
	"nutmix_remote_signer/database"
	"sort"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/elnosh/gonuts/crypto"
	"github.com/lescuer97/nutmix/api/cashu"
)

func DeriveKeysetId(keysets []*secp256k1.PublicKey) (string, error) {
	concatBinaryArray := []byte{}
	for _, pubkey := range keysets {
		if pubkey == nil {
			panic("pubkey should have never been nil at this time")
		}
		concatBinaryArray = append(concatBinaryArray, pubkey.SerializeCompressed()...)
	}
	hashedKeysetId := sha256.Sum256(concatBinaryArray)
	hex := hex.EncodeToString(hashedKeysetId[:])

	return "00" + hex[:14], nil
}

func DeriveKeysetIdV2(pubKeysArray []*secp256k1.PublicKey, unit string, finalExpiry *time.Time) string {
	var keysetIDBytes []byte

	for _, key := range pubKeysArray {
		if key == nil {
			panic("pubkey should have never been nil at this time")
		}
		keysetIDBytes = append(keysetIDBytes, key.SerializeCompressed()...)
	}

	keysetIDBytes = append(keysetIDBytes, []byte("unit:"+unit)...)
	if finalExpiry != nil {
		keysetIDBytes = append(keysetIDBytes, []byte("final_expiry:"+strconv.Itoa(int(finalExpiry.Unix())))...)
	}
	hash := sha256.Sum256(keysetIDBytes)
	return "01" + hex.EncodeToString(hash[:])
}

func convertPubkeysMapToOrderArray(raw map[uint64]*secp256k1.PublicKey) []*secp256k1.PublicKey {
	arrays := []struct {
		Amount uint64
		Pubkey *secp256k1.PublicKey
	}{}
	for amount, pubkey := range raw {

		arrays = append(arrays, struct {
			Amount uint64
			Pubkey *secp256k1.PublicKey
		}{
			Amount: amount,
			Pubkey: pubkey,
		})

	}

	sort.Slice(arrays, func(i, j int) bool {
		return arrays[i].Amount < arrays[j].Amount
	})

	justPubkeys := []*secp256k1.PublicKey{}

	for i := range arrays {
		justPubkeys = append(justPubkeys, arrays[i].Pubkey)
	}

	return justPubkeys
}

func DeriveKeyset(mintKey *hdkeychain.ExtendedKey, seed database.Seed) (MintKeyset, error) {
	keyset := MintKeyset{
		Unit:              seed.Unit,
		InputFeePpk:       seed.InputFeePpk,
		Active:            seed.Active,
		DerivationPathIdx: uint32(seed.Version),
		Keys:              make(map[uint64]crypto.KeyPair),
		Amounts:           seed.Amounts,
		Version:           seed.Version,
		FinalExpiry:       seed.FinalExpiry,
	}

	slog.Debug("converting unit to cashu unit", slog.String("unit", seed.Unit))
	unit, err := cashu.UnitFromString(seed.Unit)
	if err != nil {
		return keyset, fmt.Errorf("UnitFromString(seed.Unit) %w", err)
	}

	amountsMap := OrderAndTransformAmounts(seed.Amounts)
	if unit == cashu.AUTH {
		newMap := make(KeysetAmounts)
		newMap[1] = 0
		amountsMap = newMap
	}

	if seed.Legacy {
		slog.Info("Generating Legacy keys", slog.String("keyId", seed.Id), slog.String("amount", fmt.Sprintf("%v", seed.Amounts)))
		err := LegacyKeyDerivation(mintKey, &keyset, seed, unit, amountsMap)
		if err != nil {
			return keyset, fmt.Errorf("LegacyKeyDerivation(mintKey,&keyset, seed, unit ) %w", err)
		}
	} else {
		slog.Info("Genating keys.", slog.String("keyId", seed.Id), slog.String("amount", fmt.Sprintf("%v", seed.Amounts)))
		err := KeyDerivation(mintKey, &keyset, seed, unit, amountsMap)
		if err != nil {
			return keyset, fmt.Errorf("KeyDerivation(mintKey,&keyset, seed, unit) %w", err)
		}
	}

	publicKeys := make(map[uint64]*secp256k1.PublicKey)
	for i, val := range keyset.Keys {
		publicKeys[i] = val.PublicKey
	}

	publicKeysList := convertPubkeysMapToOrderArray(publicKeys)
	// INFO: if the seed id doesn't exists we generate it. we check the version byte and generate
	id := ""
	if len(seed.Id) == 0 {
		id, err = DeriveKeysetId(publicKeysList)
		if err != nil {
			return keyset, fmt.Errorf("DeriveKeysetId(publicKeysList) %w", err)
		}
	} else {
		switch seed.Id[:2] {
		case "00":
			id, err = DeriveKeysetId(publicKeysList)
			if err != nil {
				return keyset, fmt.Errorf("DeriveKeysetId(publicKeysList) %w", err)
			}
		case "01":
			id = DeriveKeysetIdV2(publicKeysList, seed.Unit, seed.FinalExpiry)

		}
	}

	idBytes, err := hex.DecodeString(id)
	if err != nil {
		return keyset, fmt.Errorf("hex.DecodeString(id) %w", err)
	}

	keyset.Id = idBytes

	return keyset, nil
}

func LegacyKeyDerivation(key *hdkeychain.ExtendedKey, keyset *MintKeyset, seed database.Seed, unit cashu.Unit, amounts KeysetAmounts) error {
	unitKey, err := key.Derive(uint32(unit.EnumIndex()))

	if err != nil {
		return fmt.Errorf("mintKey.NewChildKey(uint32(unit.EnumIndex())). %w", err)
	}

	versionKey, err := unitKey.Derive(uint32(seed.Version))
	if err != nil {
		return fmt.Errorf("mintKey.NewChildKey(uint32(seed.Version)) %w", err)
	}

	err = GenerateKeypairsLegacy(versionKey, amounts, keyset)
	if err != nil {
		return fmt.Errorf(`GenerateKeypairs(versionKey, values, &keyset) %w`, err)
	}
	keyset.Version = seed.Version
	return nil
}

func GenerateKeypairsLegacy(versionKey *hdkeychain.ExtendedKey, values KeysetAmounts, keyset *MintKeyset) error {
	for value, i := range values {
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

const PeanutUTF8 = uint32(129372)

func ParseUnitToIntegerReference(unit cashu.Unit) uint32 {
	unitSha256 := sha256.Sum256([]byte(unit.String()))
	unitInteger := binary.BigEndian.Uint32(unitSha256[:4])
	return unitInteger
}

func KeyDerivation(key *hdkeychain.ExtendedKey, keyset *MintKeyset, seed database.Seed, unit cashu.Unit, amounts KeysetAmounts) error {
	peanutKey, err := key.Derive(hdkeychain.HardenedKeyStart + PeanutUTF8)
	if err != nil {
		return fmt.Errorf("mintKey.NewChildKey(uint32(unit.EnumIndex())). %w", err)
	}
	unitInteger := ParseUnitToIntegerReference(unit)

	unitKey, err := peanutKey.Derive(hdkeychain.HardenedKeyStart + uint32(unitInteger))
	if err != nil {
		return fmt.Errorf("mintKey.NewChildKey(uint32(unit.EnumIndex())). %w", err)
	}

	versionKey, err := unitKey.Derive(hdkeychain.HardenedKeyStart + uint32(seed.Version))
	if err != nil {
		return fmt.Errorf("mintKey.NewChildKey(uint32(seed.Version)) %w", err)
	}

	err = GenerateKeypairs(versionKey, amounts, keyset)
	if err != nil {
		return fmt.Errorf(`GenerateKeypairs(versionKey, values, &keyset) %w`, err)
	}
	keyset.Version = seed.Version
	return nil
}

func GenerateKeypairs(versionKey *hdkeychain.ExtendedKey, values KeysetAmounts, keyset *MintKeyset) error {
	for value, i := range values {
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

func GetKeysetsFromSeeds(seeds []database.Seed, mintKey *hdkeychain.ExtendedKey) (map[string]MintPublicKeyset, map[string]MintPublicKeyset, error) {
	newKeysets := make(map[string]MintPublicKeyset)
	newActiveKeysets := make(map[string]MintPublicKeyset)

	for _, seed := range seeds {
		keyset, err := DeriveKeyset(mintKey, seed)
		if err != nil {
			return newKeysets, newActiveKeysets, fmt.Errorf("DeriveKeyset(mintKey, seed) %w", err)
		}

		if hex.EncodeToString(keyset.Id) != seed.Id {
			log.Panicf("The ids should be same. Keyset.Id: %v. Seed.Id: %v", keyset.Id, seed.Id)
		}

		publicKeyset := MakeMintPublickeys(keyset)
		publicKeyset.Legacy = seed.Legacy

		if seed.Active {
			newActiveKeysets[seed.Id] = publicKeyset
		}

		newKeysets[seed.Id] = publicKeyset

	}
	return newKeysets, newActiveKeysets, nil
}

const DefaultMaxOrder = uint32(64)

// key is the amount and I is the index for derivation
type KeysetAmounts = map[uint64]int

func OrderAndTransformAmounts(amounts []uint64) KeysetAmounts {
	// Sort the amounts
	sort.Slice(amounts, func(i, j int) bool { return amounts[i] < amounts[j] })

	// Transform to KeysetAmounts
	keysetAmounts := make(KeysetAmounts)
	for index, amount := range amounts {
		keysetAmounts[amount] = index
	}

	return keysetAmounts
}

func GetAmountsFromMaxOrder(max_order uint32) []uint64 {
	keys := make([]uint64, 0)

	for i := 0; i < int(max_order); i++ {
		keys = append(keys, uint64(math.Pow(2, float64(i))))
	}
	return keys
}

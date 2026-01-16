package signer

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math"
	"nutmix_remote_signer/database"
	"nutmix_remote_signer/utils"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/elnosh/gonuts/crypto"
	"github.com/lescuer97/nutmix/api/cashu"
	"github.com/tyler-smith/go-bip39"
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

type pubkeyWithAmount struct {
	Amount uint64
	Pubkey *secp256k1.PublicKey
}

func sortPubkeyMapToOrganizedArray(pubkeyMap map[uint64]*secp256k1.PublicKey) []pubkeyWithAmount {
	arrayPubkeys := make([]pubkeyWithAmount, len(pubkeyMap))

	i := 0
	for amount, key := range pubkeyMap {
		arrayPubkeys[i] = pubkeyWithAmount{
			Amount: amount,
			Pubkey: key,
		}
		i++
	}

	slices.SortFunc(arrayPubkeys, func(a, b pubkeyWithAmount) int {
		return int(a.Amount) - int(b.Amount)
	})
	return arrayPubkeys

}

func generateKeysetV2Preimage(sortedPubkeyArray []pubkeyWithAmount, unit string, fee uint, finalExpiry *time.Time) string {
	preimage := ""
	for i := range sortedPubkeyArray {
		preimage += fmt.Sprintf("%v:%x", sortedPubkeyArray[i].Amount, sortedPubkeyArray[i].Pubkey.SerializeCompressed())
		if i != len(sortedPubkeyArray)-1 {
			preimage += ","
		}
	}

	preimage += fmt.Sprintf("|unit:%s", unit)
	if fee > 0 {
		preimage += fmt.Sprintf("|input_fee_ppk:%v", fee)
	}

	if finalExpiry != nil {
		preimage += fmt.Sprintf("|final_expiry:%v", finalExpiry.Unix())
	}

	return preimage
}

func DeriveKeysetIdV2(pubKeysMap map[uint64]*secp256k1.PublicKey, unit string, fee uint, finalExpiry *time.Time) string {
	arrayPubkeys := sortPubkeyMapToOrganizedArray(pubKeysMap)
	preimage := generateKeysetV2Preimage(arrayPubkeys, unit, fee, finalExpiry)
	hash := sha256.Sum256([]byte(preimage))
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
	unit, err := cashu.UnitFromString(strings.ToLower(seed.Unit))
	if err != nil {
		return keyset, fmt.Errorf("UnitFromString(seed.Unit) %w", err)
	}

	amountsMap := OrderAndTransformAmounts(seed.Amounts)

	slog.Info("Generating Key keys.", slog.String("keyId", seed.Id), slog.String("amount", fmt.Sprintf("%v", seed.Amounts)))
	err = KeyDerivation(mintKey, &keyset, seed, unit.String(), amountsMap)
	if err != nil {
		return keyset, fmt.Errorf("KeyDerivation(mintKey,&keyset, seed, unit) %w", err)
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
			id = DeriveKeysetIdV2(publicKeys, seed.Unit, seed.InputFeePpk, seed.FinalExpiry)
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

func ParseUnitToIntegerReference(unit string) uint32 {
	unit = unitNormalization(unit)
	unitSha256 := sha256.Sum256([]byte(unit))
	unitInteger := binary.BigEndian.Uint32(unitSha256[:4])
	return unitInteger &^ (1 << 31)
}

func KeyDerivation(key *hdkeychain.ExtendedKey, keyset *MintKeyset, seed database.Seed, unit string, amounts KeysetAmounts) error {
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

func GetMasterKey() (*hdkeychain.ExtendedKey, error) {
	seedFromDBUS, err := getNutmixSignerKey()
	defer func() {
		seedFromDBUS = ""
	}()
	if err != nil {
		return nil, fmt.Errorf("signer.getSignerPrivateKey(). %w", err)
	}

	if !bip39.IsMnemonicValid(seedFromDBUS) {
		return nil, errors.New("mnemonic is not valid or not in English")
	}
	seedBytes := bip39.NewSeed(seedFromDBUS, "")

	slog.Debug("Creating master key for derivation")
	masterKey, err := hdkeychain.NewMaster(seedBytes, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf(" bip32.NewMasterKey(privateKey.Serialize()). %w", err)
	}
	return masterKey, nil
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
			log.Panicf("The ids should be same. Keyset.Id: %x. Seed.Id: %v", keyset.Id, seed.Id)
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

const DefaultMaxOrder = uint32(32)

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

func unitStringCollissionCheck(keysets []MintPublicKeyset, newUnit string) error {
	keysetsSet := make(map[string]struct{})
	for i := range keysets {
		keysetsSet[keysets[i].Unit] = struct{}{}
	}

	_, exists := keysetsSet[newUnit]
	if exists {
		return nil
	}

	newUnitInt := ParseUnitToIntegerReference(newUnit)
	log.Println("newUnitInt: ", newUnitInt)
	for unit := range keysetsSet {
		if ParseUnitToIntegerReference(unit) == newUnitInt {
			return fmt.Errorf("%w. unit: %v", utils.ErrUnitStringCollision, newUnit)
		}
	}

	return nil
}

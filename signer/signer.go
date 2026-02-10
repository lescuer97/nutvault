package signer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"nutmix_remote_signer/database"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	goNutsCashu "github.com/elnosh/gonuts/cashu"
	"github.com/elnosh/gonuts/cashu/nuts/nut10"
	"github.com/elnosh/gonuts/cashu/nuts/nut11"
	"github.com/elnosh/gonuts/cashu/nuts/nut14"
	"github.com/elnosh/gonuts/crypto"
	"github.com/lescuer97/nutmix/api/cashu"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/text/unicode/norm"
)

type KeysetGenerationIndexes map[string]map[uint64]int
type Signer struct {
	store  *KeysetStore
	db     database.SqliteDB
	pubkey *secp256k1.PublicKey
}

func SetupLocalSigner(db database.SqliteDB, config Config) (Signer, error) {
	signer := Signer{
		db:    db,
		store: NewKeysetStore(),
	}

	err := SetupKeychain()
	if err != nil {
		return signer, fmt.Errorf("SetupKeychain(). %w", err)
	}

	slog.Info("Trying to get the Mint key")
	// mint_privkey := os.Getenv("MINT_PRIVATE_KEY")
	seedFromLibSecret, err := getNutmixSignerKey()
	defer func() {
		seedFromLibSecret = ""
	}()

	if err != nil {
		if errors.Is(err, ErrNotFound) {
			slog.Warn("seedphrase was not found in store. looking for one or generating one.", slog.Any("error", err))
			seedFromLibSecret, err = signer.findOrGenerateANewSeedphrase()
			if err != nil {
				return signer, fmt.Errorf("signer.findOrGenerateANewSeedphrase(). %w", err)
			}
		} else {
			return signer, fmt.Errorf("signer.getSignerPrivateKey(). %w", err)
		}
	}

	if !bip39.IsMnemonicValid(seedFromLibSecret) {
		return signer, errors.New("mnemonic is not valid or not in English")
	}
	seedBytes := bip39.NewSeed(seedFromLibSecret, "")
	slog.Debug("Creating master key for derivation")
	masterKey, err := hdkeychain.NewMaster(seedBytes, &chaincfg.MainNetParams)
	defer func() {
		masterKey = nil
	}()
	if err != nil {
		return signer, fmt.Errorf(" bip32.NewMasterKey(privateKey.Serialize()). %w", err)
	}

	seeds, err := signer.db.GetAllSeeds()
	if err != nil {
		return signer, fmt.Errorf("signer.db.GetAllSeeds(). %w", err)
	}

	if len(seeds) == 0 {
		slog.Info("There are no seeds available.")

		slog.Debug("Generating amounts for new seed")

		amounts := GetAmountsFromMaxOrder(DefaultMaxOrder)

		slog.Info("Creating a new seed")
		newSeed, err := signer.createNewSeed(masterKey, cashu.Sat, 0, 0, amounts, config.ExpireTime)

		if err != nil {
			return signer, fmt.Errorf("signer.createNewSeed(masterKey, 1, 0). %w", err)
		}

		tx, err := db.Db.Begin()
		if err != nil {
			return signer, fmt.Errorf("l.db.GetTx(ctx). %w", err)
		}
		defer func() {
			_ = tx.Rollback()
		}()

		slog.Info("Saving seed for to the database")
		err = db.SaveNewSeed(tx, newSeed)
		if err != nil {
			return signer, fmt.Errorf("db.SaveNewSeeds([]cashu.Seed{newSeed}). %w", err)
		}
		err = tx.Commit()
		if err != nil {
			return signer, fmt.Errorf(`tx.Commit(). %w`, err)
		}
		seeds = append(seeds, newSeed)
	}
	keysets, activeKeysets, err := GetKeysetsFromSeeds(seeds, masterKey)
	if err != nil {
		return signer, fmt.Errorf(`signer.GetKeysetsFromSeeds(seeds, masterKey). %w`, err)
	}

	// store keysets and indexes in the concurrency-safe store
	signer.store.SetAll(keysets, activeKeysets)
	signer.store.SetIndexesFromSeeds(seeds)

	// Start background watcher (in separate goroutine) to rotate keysets when their FinalExpiry passes.
	if config.AutoRotate && config.ExpireTime != nil {
		slog.Debug("auto rotate activated starting watcher")
		go signer.startWatcher(config.ExpireTime)
	}

	slog.Debug("Setting keysets into the signer")
	pubkey, err := masterKey.ECPubKey()
	if err != nil {
		return signer, fmt.Errorf(`masterKey.ECPubKey(). %w`, err)
	}
	// already stored in signer.store earlier
	signer.pubkey = pubkey

	return signer, nil
}

// startWatcher starts the background loop that checks active keysets and
// rotates any whose FinalExpiry has passed.
func (s *Signer) startWatcher(expiry_time *time.Time) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		activeCopy := s.store.GetActiveKeysetsCopy()
		for _, ks := range activeCopy {
			if ks.FinalExpiry.IsZero() || ks.FinalExpiry.After(now) {
				continue
			}
			unitStr := strings.ToLower(ks.Unit)

			unit, err := cashu.UnitFromString(unitStr)
			if err != nil {
				slog.Error("Could not parse unit for expired keyset", slog.String("unit", ks.Unit), slog.String("err", err.Error()))
				continue
			}

			fee := uint64(ks.InputFeePpk)
			amounts := make([]uint64, 0, len(ks.Keys))
			for a := range ks.Keys {
				amounts = append(amounts, a)
			}

			_, err = s.RotateKeyset(unit, fee, amounts, expiry_time)
			if err != nil {
				slog.Error("Auto-rotation failed", slog.String("unit", unitStr), slog.String("err", err.Error()))
			} else {
				slog.Info("Auto-rotation succeeded", slog.String("unit", unitStr))
			}
		}
	}
}

func (l *Signer) GetKeysets() []MintPublicKeyset {
	return l.store.GetKeysetsList()
}

func unitNormalization(unit string) string {
	// Remove leading and trailing ASCII whitespace characters (space, tab, carriage return, line feed).
	unitStr := strings.TrimSpace(unit)
	//  Apply Unicode Normalization Form C (NFC).
	unitStr = norm.NFC.String(unitStr)
	//  Convert the normalized string to uppercase using Unicode-aware semantics
	return strings.ToUpper(unitStr)

}
func (l *Signer) createNewSeed(mintPrivateKey *hdkeychain.ExtendedKey, unit cashu.Unit, version uint64, fee uint, amounts []uint64, expiry_time *time.Time) (database.Seed, error) {
	slog.Info("Generating new seed", slog.String("unit", unit.String()), slog.String("version", strconv.FormatInt(int64(version), 10)), slog.String("fee", strconv.FormatUint(uint64(fee), 10)))

	if unit == cashu.AUTH {
		amounts = []uint64{1}
	}

	// rotate one level up
	newSeed := database.Seed{
		CreatedAt:   time.Now().Unix(),
		Active:      true,
		Version:     version,
		Unit:        unitNormalization(unit.String()),
		InputFeePpk: fee,
		Legacy:      false,
		Amounts:     amounts,
		FinalExpiry: expiry_time,
	}

	keyset, err := DeriveKeyset(mintPrivateKey, newSeed)
	if err != nil {
		return newSeed, fmt.Errorf("DeriveKeyset(mintPrivateKey, newSeed) %w", err)
	}

	if len(keyset.Id) == 0 {
		slog.Error("Keyset id should already exists at this point ")
		panic("keyset id was not generated")
	}

	/// check for collision
	keysets := l.GetKeysets()

	err = unitStringCollissionCheck(keysets, newSeed.Unit)
	if err != nil {
		return newSeed, fmt.Errorf("unitStringCollissionCheck(keysets, newSeed.Unit) %w", err)
	}

	newSeed.Id = hex.EncodeToString(keyset.Id)
	return newSeed, nil

}

func (l *Signer) RotateKeyset(unit cashu.Unit, fee uint64, amounts []uint64, expiry_time *time.Time) (MintPublicKeyset, error) {
	slog.Info("Rotating keyset", slog.String("unit", unit.String()), slog.String("fee", strconv.FormatUint(fee, 10)))
	newKey := MintPublicKeyset{}

	tx, err := l.db.Db.Begin()
	if err != nil {
		return newKey, fmt.Errorf("l.db.GetTx(ctx). %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// get current highest seed version
	highestSeedVersion := uint64(0)
	slog.Debug("Getting seed from unit", slog.String("unit", unit.String()))
	seeds, err := l.db.GetSeedsByUnit(tx, unit)
	if err != nil {
		return newKey, fmt.Errorf("database.GetSeedsByUnit(tx, unit). %w", err)
	}
	slog.Debug("Finding highest current version of seed")
	for i, seed := range seeds {
		if highestSeedVersion <= seed.Version {
			highestSeedVersion = seed.Version + uint64(1)
		}

		seeds[i].Active = false
	}

	slog.Info(fmt.Sprintf("Current hightest seed. Version: %v. ", highestSeedVersion))

	masterKey, err := GetMasterKey()
	defer func() {
		masterKey = nil
	}()
	if err != nil {
		return newKey, fmt.Errorf(" bip32.NewMasterKey(privateKey.Serialize()). %w", err)
	}

	// Create New seed with one higher version
	newSeed, err := l.createNewSeed(masterKey, unit, highestSeedVersion, uint(fee), amounts, expiry_time)

	if err != nil {
		return newKey, fmt.Errorf(`l.createNewSeed(signerMasterKey, unit, highestSeed.Version+1, fee) %w`, err)
	}

	// add new key to db
	err = l.db.SaveNewSeed(tx, newSeed)
	if err != nil {
		return newKey, fmt.Errorf(`l.db.SaveNewSeed(tx, newSeed). %w`, err)
	}

	// only need to update if there are any previous seeds
	if len(seeds) > 0 {
		err = l.db.UpdateSeedsActiveStatus(tx, seeds)
		if err != nil {
			return newKey, fmt.Errorf(`l.db.UpdateSeedsActiveStatus(tx, seeds). %w`, err)
		}
	}

	err = tx.Commit()
	if err != nil {
		return newKey, fmt.Errorf(`tx.Commit(). %w`, err)
	}
	seeds = append(seeds, newSeed)

	keysets, activeKeysets, err := GetKeysetsFromSeeds(seeds, masterKey)
	if err != nil {
		return newKey, fmt.Errorf(`m.DeriveKeysetFromSeeds(seeds, parsedPrivateKey). %w`, err)
	}

	// Parse the seeds to get the amounts indexes
	// store indexes in the keyset store
	l.store.SetIndexesFromSeeds(seeds)

	// update store with newly derived keysets
	l.store.SetAll(keysets, activeKeysets)

	return func() (MintPublicKeyset, error) {
		ks, ok := l.store.GetKeysetById(newSeed.Id)
		if !ok {
			return MintPublicKeyset{}, fmt.Errorf("keyset not found after rotation: %s", newSeed.Id)
		}
		return ks, nil
	}()
}

func (l *Signer) SignBlindMessages(messages goNutsCashu.BlindedMessages) (goNutsCashu.BlindedSignatures, error) {
	var blindedSignatures goNutsCashu.BlindedSignatures

	indexesForGeneration := make(KeysetGenerationIndexes)

	slog.Debug("Finding what amounts we need to create private keys for")
	// get generation index from the stored index in the signer
	for _, output := range messages {
		keyset, keysetExits := l.store.GetIndex(output.Id)
		if !keysetExits {
			return nil, fmt.Errorf("keyset does not exist: Id: %+v", output.Id)
		}
		_, exists := indexesForGeneration[output.Id]
		if !exists {
			indexesForGeneration[output.Id] = make(map[uint64]int)
		}
		i, amountExists := keyset[output.Amount]
		if amountExists {
			indexesForGeneration[output.Id][output.Amount] = i
		} else {
			return nil, fmt.Errorf("no index was found for this amount: %+v", output.Amount)
		}
	}

	keysets, err := l.GenerateMintKeysFromPublicKeysets(indexesForGeneration)
	defer func() {
		keysets = nil
	}()
	if err != nil {
		err = fmt.Errorf("l.GenerateMintKeysFromPublicKeysets(indexesForGeneration): %w", err)
		return nil, err
	}

	slog.Debug("Signing blind messages")
	for _, output := range messages {
		correctKeyset := keysets[output.Id].Keys[output.Amount]

		if correctKeyset.PrivateKey == nil || !keysets[output.Id].Active {
			return nil, cashu.UsingInactiveKeyset
		}

		pubkeyBytes, err := hex.DecodeString(output.B_)
		if err != nil {
			err = fmt.Errorf("hex.DecodeString(output.B_): %w %w", cashu.ErrInvalidBlindMessage, err)
			return nil, err
		}

		blindedMsg, err := secp256k1.ParsePubKey(pubkeyBytes)
		if err != nil {
			err = fmt.Errorf("secp256k1.ParsePubKey(serializedPubkey): %w %w", cashu.ErrInvalidBlindMessage, err)
			return nil, err
		}

		sig := crypto.SignBlindedMessage(blindedMsg, correctKeyset.PrivateKey)

		E, S := crypto.GenerateDLEQ(correctKeyset.PrivateKey, blindedMsg, sig)

		dleq := goNutsCashu.DLEQProof{
			E: hex.EncodeToString(E.Serialize()),
			S: hex.EncodeToString(S.Serialize()),
		}

		blindedSignatures = append(blindedSignatures,
			goNutsCashu.BlindedSignature{Amount: output.Amount,
				Id:   output.Id,
				C_:   hex.EncodeToString(sig.SerializeCompressed()),
				DLEQ: &dleq,
			})

	}
	return blindedSignatures, nil

}

func (l *Signer) VerifyProofs(proofs goNutsCashu.Proofs, blindMessages goNutsCashu.BlindedMessages) error {
	indexesForGeneration := make(KeysetGenerationIndexes)

	slog.Debug("Finding what amounts we need to create private keys for")
	// get index of amounts to use for generation
	for _, proof := range proofs {
		keyset, keysetExits := l.store.GetIndex(proof.Id)
		if !keysetExits {
			return fmt.Errorf("keyset does not exist: Id: %+v", proof.Id)
		}
		_, exists := indexesForGeneration[proof.Id]
		if !exists {
			indexesForGeneration[proof.Id] = make(map[uint64]int)
		}
		i, amountExists := keyset[proof.Amount]
		if amountExists {
			indexesForGeneration[proof.Id][proof.Amount] = i
		} else {
			return fmt.Errorf("no index was found for this amount: %+v", proof.Amount)
		}
	}

	keysets, err := l.GenerateMintKeysFromPublicKeysets(indexesForGeneration)
	defer func() {
		keysets = nil
	}()
	if err != nil {
		err = fmt.Errorf("l.GenerateMintKeysFromPublicKeysets(indexesForGeneration): %w", err)
		return err
	}

	slog.Debug("Validating proofs")
	for _, proof := range proofs {
		err := l.validateProof(keysets, proof)
		if err != nil {
			return fmt.Errorf("l.validateProof(proof, unit, &checkOutputs, &pubkeysFromProofs): %w", err)
		}
	}

	return nil
}

func (l *Signer) validateProof(keysets map[string]MintKeyset, proof goNutsCashu.Proof) error {
	keyset, exists := keysets[proof.Id]
	if !exists {
		return cashu.ErrKeysetForProofNotFound
	}

	keypair := keyset.Keys[proof.Amount]
	unBlindedBytes, err := hex.DecodeString(proof.C)
	if err != nil {
		err = fmt.Errorf("hex.DecodeString(proof.C) %w %w", cashu.ErrInvalidProof, err)
		return err
	}

	unBlindedSig, err := secp256k1.ParsePubKey(unBlindedBytes)
	if err != nil {
		err = fmt.Errorf("secp256k1.ParsePubKey(unBlindedBytes): %w %w", cashu.ErrInvalidProof, err)
		return err
	}

	bool := crypto.Verify(proof.Secret, keypair.PrivateKey, unBlindedSig)
	if !bool {
		err = fmt.Errorf("crypto.Verify(proof.Secret, keypair.PrivateKey, unBlindedSig): %w %w", cashu.ErrInvalidProof, err)
		return err
	}

	nut10Secret, err := nut10.DeserializeSecret(proof.Secret)
	if err == nil {
		slog.Debug("Checking if the proof is locked")
		switch nut10Secret.Kind {
		case nut10.P2PK:
			slog.Debug("Proof locked to P2PK")
			if err := verifyP2PKLockedProof(proof, nut10Secret); err != nil {
				return fmt.Errorf("verifyP2PKLockedProof(proof, nut10Secret); err != nil : %w %w", cashu.ErrInvalidProof, err)
			}
		case nut10.HTLC:
			slog.Debug("Proof locked to HTLC")
			if err := verifyHTLCProof(proof, nut10Secret); err != nil {
				return fmt.Errorf("verifyP2PKLockedProof(proof, nut10Secret); err != nil ; err != nil : %w %w", cashu.ErrInvalidProof, err)
			}
		}
	}

	return nil
}

// returns serialized compressed public key
func (l *Signer) GetSignerPubkey() []byte {
	return l.pubkey.SerializeCompressed()
}

// returns serialized compressed public key
func (l *Signer) findOrGenerateANewSeedphrase() (string, error) {
	env_mnemonic := os.Getenv("MNEMONIC")
	defer func() {
		env_mnemonic = ""
	}()

	if len(env_mnemonic) > 0 {
		if !bip39.IsMnemonicValid(env_mnemonic) {
			return "", fmt.Errorf("invalid mnemonic seedphrase")
		}
		err := StoreSeedPhrase(env_mnemonic)
		if err != nil {
			return "", fmt.Errorf("StoreSeedPhrase(mnemonic). %w", err)

		}
		return env_mnemonic, nil
	}

	entropy, err := bip39.NewEntropy(256)
	defer func() {
		entropy = nil
	}()
	if err != nil {
		return "", fmt.Errorf("bip39.NewEntropy(256). %w", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("bip39.NewMnemonic(entropy). %w", err)
	}
	err = StoreSeedPhrase(mnemonic)
	if err != nil {
		return "", fmt.Errorf("StoreSeedPhrase(mnemonic). %w", err)

	}
	return mnemonic, nil
}

func verifyP2PKLockedProof(proof goNutsCashu.Proof, proofSecret nut10.WellKnownSecret) error {
	var p2pkWitness nut11.P2PKWitness
	err := json.Unmarshal([]byte(proof.Witness), &p2pkWitness)
	if err != nil {
		return err
	}
	p2pkTags, err := nut11.ParseP2PKTags(proofSecret.Data.Tags)
	if err != nil {
		return err
	}

	signaturesRequired := 1
	// if locktime is expired and there is no refund pubkey, treat as anyone can spend
	// if refund pubkey present, check signature
	if p2pkTags.Locktime > 0 && time.Now().Local().Unix() > p2pkTags.Locktime {
		if len(p2pkTags.Refund) == 0 {
			return nil
		} else {
			hash := sha256.Sum256([]byte(proof.Secret))
			if len(p2pkWitness.Signatures) < 1 {
				return nut11.InvalidWitness
			}
			if !nut11.HasValidSignatures(hash[:], p2pkWitness.Signatures, signaturesRequired, p2pkTags.Refund) {
				return nut11.NotEnoughSignaturesErr
			}
		}
	} else {
		pubkey, err := nut11.ParsePublicKey(proofSecret.Data.Data)
		if err != nil {
			return err
		}
		keys := []*btcec.PublicKey{pubkey}
		// message to sign
		hash := sha256.Sum256([]byte(proof.Secret))

		if p2pkTags.NSigs > 0 {
			signaturesRequired = p2pkTags.NSigs
			if len(p2pkTags.Pubkeys) == 0 {
				return nut11.EmptyPubkeysErr
			}
			keys = append(keys, p2pkTags.Pubkeys...)
		}

		if len(p2pkWitness.Signatures) < 1 {
			return nut11.InvalidWitness
		}

		if nut11.DuplicateSignatures(p2pkWitness.Signatures) {
			return nut11.DuplicateSignaturesErr
		}

		if !nut11.HasValidSignatures(hash[:], p2pkWitness.Signatures, signaturesRequired, keys) {
			return nut11.NotEnoughSignaturesErr
		}
	}
	return nil
}

func verifyHTLCProof(proof goNutsCashu.Proof, proofSecret nut10.WellKnownSecret) error {
	var htlcWitness nut14.HTLCWitness
	err := json.Unmarshal([]byte(proof.Witness), &htlcWitness)

	if err != nil {
		return err
	}
	p2pkTags, err := nut11.ParseP2PKTags(proofSecret.Data.Tags)
	if err != nil {
		return err
	}

	// if locktime is expired and there is no refund pubkey, treat as anyone can spend
	// if refund pubkey present, check signature
	if p2pkTags.Locktime > 0 && time.Now().Local().Unix() > p2pkTags.Locktime {
		if len(p2pkTags.Refund) == 0 {
			return nil
		} else {
			hash := sha256.Sum256([]byte(proof.Secret))
			if len(htlcWitness.Signatures) < 1 {
				return nut11.InvalidWitness
			}
			if !nut11.HasValidSignatures(hash[:], htlcWitness.Signatures, 1, p2pkTags.Refund) {
				return nut11.NotEnoughSignaturesErr
			}
		}
		return nil
	}

	// verify valid preimage
	preimageBytes, err := hex.DecodeString(htlcWitness.Preimage)
	if err != nil {
		return nut14.InvalidPreimageErr
	}
	hashBytes := sha256.Sum256(preimageBytes)
	hash := hex.EncodeToString(hashBytes[:])

	if len(proofSecret.Data.Data) != 64 {
		return nut14.InvalidHashErr
	}
	if hash != proofSecret.Data.Data {
		return nut14.InvalidPreimageErr
	}

	// if n_sigs flag present, verify signatures
	if p2pkTags.NSigs > 0 {
		if len(htlcWitness.Signatures) < 1 {
			return nut11.NoSignaturesErr
		}

		hash := sha256.Sum256([]byte(proof.Secret))

		if nut11.DuplicateSignatures(htlcWitness.Signatures) {
			return nut11.DuplicateSignaturesErr
		}

		if !nut11.HasValidSignatures(hash[:], htlcWitness.Signatures, p2pkTags.NSigs, p2pkTags.Pubkeys) {
			return nut11.NotEnoughSignaturesErr
		}
	}

	return nil
}

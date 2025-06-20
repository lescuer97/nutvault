package signer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"nutmix_remote_signer/database"
	"strconv"
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
	"github.com/jackc/pgx/v5"
	"github.com/lescuer97/nutmix/api/cashu"
	"github.com/tyler-smith/go-bip39"
)

type KeysetGenerationIndexes map[string]map[uint64]int
type Signer struct {
	keysets       map[string]MintPublicKeyset
	activeKeysets map[string]MintPublicKeyset
	db            database.SqliteDB
	pubkey        *secp256k1.PublicKey
	// this is used to rapidly calculate what indexes are needed for keyderivation
	keysetIndexes KeysetGenerationIndexes
}

func SetupLocalSigner(db database.SqliteDB) (Signer, error) {
	signer := Signer{
		db: db,
	}
	slog.Info("Trying to get the Mint key")
	// mint_privkey := os.Getenv("MINT_PRIVATE_KEY")
	seedFromDbus, err := GetNutmixSignerKey()
	if err != nil {
		return signer, fmt.Errorf("signer.getSignerPrivateKey(). %w", err)
	}

	privateKey, err := signer.getSignerPrivateKey(seedFromDbus)
	if err != nil {
		return signer, fmt.Errorf("signer.getSignerPrivateKey(). %w", err)
	}
	slog.Debug("Creating master key for derivation")
	masterKey, err := hdkeychain.NewMaster(privateKey.Serialize(), &chaincfg.MainNetParams)
	if err != nil {
		return signer, fmt.Errorf(" bip32.NewMasterKey(privateKey.Serialize()). %w", err)
	}
	defer func() {
		slog.Debug("Cleaning up priv key variables")
		seedFromDbus = ""
		privateKey = nil
		masterKey = nil
	}()

	slog.Debug("Getting all the seeds from the database")
	seeds, err := signer.db.GetAllSeeds()
	if err != nil {
		return signer, fmt.Errorf("signer.db.GetAllSeeds(). %w", err)
	}
	signer.keysetIndexes = make(KeysetGenerationIndexes)
	if len(seeds) == 0 {
		slog.Info("There are no seeds available.")

		slog.Debug("Generating amounts for new seed")

		amounts := GetAmountsFromMaxOrder(DefaultMaxOrder)

		slog.Info("Creating a new seed")
		newSeed, err := signer.createNewSeed(masterKey, cashu.Sat, 1, 0, amounts)

		if err != nil {
			return signer, fmt.Errorf("signer.createNewSeed(masterKey, 1, 0). %w", err)
		}

		tx, err := db.Db.Begin()
		if err != nil {
			return signer, fmt.Errorf("l.db.GetTx(ctx). %w", err)
		}
		defer tx.Rollback()

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

	slog.Debug("Generating keysets from seeds")
	keysets, activeKeysets, err := GetKeysetsFromSeeds(seeds, masterKey)
	if err != nil {
		return signer, fmt.Errorf(`signer.GetKeysetsFromSeeds(seeds, masterKey). %w`, err)
	}

	// Parse the seeds to get the amounts indexes
	for _, seed := range seeds {
		for index, val := range seed.Amounts {
			_, exists := signer.keysetIndexes[seed.Id]
			if !exists {
				signer.keysetIndexes[seed.Id] = make(map[uint64]int)
				signer.keysetIndexes[seed.Id][val] = index
			} else {
				signer.keysetIndexes[seed.Id][val] = index

			}
		}
	}

	slog.Debug("Setting keysets into the signer")
	signer.keysets = keysets
	signer.activeKeysets = activeKeysets
	signer.pubkey = privateKey.PubKey()

	return signer, nil
}

func (l *Signer) GetKeysets() []MintPublicKeyset {
	response := []MintPublicKeyset{}
	for _, mintkey := range l.keysets {
		response = append(response, mintkey)
	}

	return response
}

func (l *Signer) getSignerPrivateKey(seed string) (*secp256k1.PrivateKey, error) {
	slog.Debug("parsing private_key")
	seedBytes, err := bip39.EntropyFromMnemonic(seed)
	if err != nil {
		return nil, fmt.Errorf(`bip39.EntropyFromMnemonic(seed). %w`, err)
	}
	mintKey := secp256k1.PrivKeyFromBytes(seedBytes)
	return mintKey, nil
}

func (l *Signer) createNewSeed(mintPrivateKey *hdkeychain.ExtendedKey, unit cashu.Unit, version int, fee uint, amounts []uint64) (database.Seed, error) {
	slog.Info("Generating new seed", slog.String("unit", unit.String()), slog.String("version", strconv.FormatInt(int64(version), 10)), slog.String("fee", strconv.FormatUint(uint64(fee), 10)))
	// rotate one level up
	newSeed := database.Seed{
		CreatedAt:   time.Now().Unix(),
		Active:      true,
		Version:     version,
		Unit:        unit.String(),
		InputFeePpk: fee,
		Legacy:      false,
		Amounts:     amounts,
	}

	keyset, err := DeriveKeyset(mintPrivateKey, newSeed, amounts)
	if err != nil {
		return newSeed, fmt.Errorf("DeriveKeyset(mintPrivateKey, newSeed) %w", err)
	}

	if len(keyset.Id) == 0 {
		slog.Error("Keyset id should already exists at this point ")
		panic("keyset id was not generated")
	}

	newSeed.Id = hex.EncodeToString(keyset.Id)
	return newSeed, nil

}

func (l *Signer) RotateKeyset(unit cashu.Unit, fee uint64, amounts []uint64) (MintPublicKeyset, error) {
	slog.Info("Rotating keyset", slog.String("unit", unit.String()), slog.String("fee", strconv.FormatUint(uint64(fee), 10)))
	newKey := MintPublicKeyset{}
	// if max_order > DefaultMaxOrder {
	// 	return newKey, utils.ErrAboveMaxOrder
	// }

	tx, err := l.db.Db.Begin()
	if err != nil {
		return newKey, fmt.Errorf("l.db.GetTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// get current highest seed version
	var highestSeed database.Seed = database.Seed{Version: 0}
	slog.Debug("Getting seed from unit", slog.String("unit", unit.String()))
	seeds, err := l.db.GetSeedsByUnit(tx, unit)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return newKey, fmt.Errorf("database.GetSeedsByUnit(tx, unit). %w", err)
		}
	}
	slog.Debug("Finding highest current version of seed")
	for i, seed := range seeds {
		if highestSeed.Version < seed.Version {
			highestSeed = seed
		}

		seeds[i].Active = false
	}

	slog.Info(fmt.Sprintf("Current hightest seed. Version: %v. Id: %s", highestSeed.Version, highestSeed.Id))

	seedFromDBUS, err := GetNutmixSignerKey()
	if err != nil {
		return newKey, fmt.Errorf("signer.getSignerPrivateKey(). %w", err)
	}

	mintPrivateKey, err := l.getSignerPrivateKey(seedFromDBUS)
	if err != nil {
		return newKey, fmt.Errorf(`l.getSignerPrivateKey() %w`, err)
	}

	signerMasterKey, err := hdkeychain.NewMaster(mintPrivateKey.Serialize(), &chaincfg.MainNetParams)
	if err != nil {
		return newKey, fmt.Errorf(" hdkeychain.NewMaster(mintPrivateKey.Serialize()). %w", err)
	}

	// Create New seed with one higher version
	newSeed, err := l.createNewSeed(signerMasterKey, unit, highestSeed.Version+1, uint(fee), amounts)

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

	seeds = append(seeds, newSeed)

	keysets, activeKeysets, err := GetKeysetsFromSeeds(seeds, signerMasterKey)
	if err != nil {
		return newKey, fmt.Errorf(`m.DeriveKeysetFromSeeds(seeds, parsedPrivateKey). %w`, err)
	}

	err = tx.Commit()
	if err != nil {
		return newKey, fmt.Errorf(`tx.Commit(). %w`, err)
	}
	// Parse the seeds to get the amounts indexes
	for _, seed := range seeds {
		for index, val := range seed.Amounts {
			l.keysetIndexes[seed.Id][val] = index
		}
	}

	l.keysets = keysets
	l.activeKeysets = activeKeysets

	signerMasterKey = nil
	return l.keysets[newSeed.Id], nil
}

func (l *Signer) SignBlindMessages(messages goNutsCashu.BlindedMessages) (goNutsCashu.BlindedSignatures, error) {
	var blindedSignatures goNutsCashu.BlindedSignatures

	indexesForGeneration := make(KeysetGenerationIndexes)

	slog.Debug("Finding what amounts we need to create private keys for")
	// get generation index from the stored index in the signer
	for _, output := range messages {
		keyset, keysetExits := l.keysetIndexes[output.Id]
		if !keysetExits {
			return nil, fmt.Errorf("Keyset does not exists: Id: %+v", output.Id)
		}
		_, exists := indexesForGeneration[output.Id]
		if !exists {
			indexesForGeneration[output.Id] = make(map[uint64]int)
		}
		i, amountExists := keyset[output.Amount]
		if amountExists {
			indexesForGeneration[output.Id][output.Amount] = i
		} else {
			return nil, fmt.Errorf("No index was found for this amount: %+v", output.Amount)
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
		keyset, keysetExits := l.keysetIndexes[proof.Id]
		if !keysetExits {
			return fmt.Errorf("Keyset does not exists: Id: %+v", proof.Id)
		}
		_, exists := indexesForGeneration[proof.Id]
		if !exists {
			indexesForGeneration[proof.Id] = make(map[uint64]int)
		}
		i, amountExists := keyset[proof.Amount]
		if amountExists {
			indexesForGeneration[proof.Id][proof.Amount] = i
		} else {
			return fmt.Errorf("No index was found for this amount: %+v", proof.Amount)
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
		if nut10Secret.Kind == nut10.P2PK {
			slog.Debug("Proof locked to P2PK")
			if err := verifyP2PKLockedProof(proof, nut10Secret); err != nil {
				return fmt.Errorf("verifyP2PKLockedProof(proof, nut10Secret); err != nil : %w %w", cashu.ErrInvalidProof, err)
			}
		} else if nut10Secret.Kind == nut10.HTLC {
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

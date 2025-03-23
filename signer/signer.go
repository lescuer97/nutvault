package signer

import (
	"encoding/hex"
	"errors"
	"fmt"
	"nutmix_remote_signer/database"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/elnosh/gonuts/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/lescuer97/nutmix/api/cashu"
	"github.com/tyler-smith/go-bip32"
)

type Signer struct {
	// activeKeysets map[id]cashu.MintKeysMap
	activeKeysets map[string]cashu.MintKeysMap
	// keyests map[id]cashu.MintKeysMap
	keysets map[string]cashu.MintKeysMap
	db      database.SqliteDB
}

func SetupLocalSigner(db database.SqliteDB) (Signer, error) {
	signer := Signer{
		db: db,
	}

	privateKey, err := signer.getSignerPrivateKey()
	if err != nil {
		return signer, fmt.Errorf("signer.getSignerPrivateKey(). %w", err)
	}
	masterKey, err := bip32.NewMasterKey(privateKey.Serialize())
	if err != nil {
		return signer, fmt.Errorf(" bip32.NewMasterKey(privateKey.Serialize()). %w", err)
	}
	seeds, err := signer.db.GetAllSeeds()
	if err != nil {
		return signer, fmt.Errorf("signer.db.GetAllSeeds(). %w", err)
	}
	if len(seeds) == 0 {
		newSeed, err := signer.createNewSeed(masterKey, cashu.Sat, 1, 0)

		if err != nil {
			return signer, fmt.Errorf("signer.createNewSeed(masterKey, 1, 0). %w", err)
		}

		tx, err := db.Db.Begin()
		if err != nil {
			return signer, fmt.Errorf("l.db.GetTx(ctx). %w", err)
		}
		defer tx.Rollback()

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

	signer.keysets = keysets
	signer.activeKeysets = activeKeysets

	masterKey = nil
	return signer, nil

}

// gets all active keys
func (l *Signer) GetActiveKeys() (GetKeysResponse, error) {
	// convert map to slice
	var keys []cashu.MintKey
	for _, keyset := range l.activeKeysets {
		for _, key := range keyset {
			keys = append(keys, key)
		}
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Amount < keys[j].Amount
	})

	return OrderKeysetByUnit(keys), nil
}

func (l *Signer) GetKeysById(id string) (GetKeysResponse, error) {

	val, exists := l.keysets[id]
	if exists {
		var keys []cashu.MintKey
		for _, key := range val {
			keys = append(keys, key)
		}

		return OrderKeysetByUnit(keys), nil

	}
	return GetKeysResponse{}, ErrNoKeysetFound
}
func (l *Signer) GetKeysByUnit(unit cashu.Unit) ([]cashu.Keyset, error) {
	var keys []cashu.Keyset

	for _, mintKey := range l.keysets {

		if len(mintKey) > 0 {

			if mintKey[0].Unit == unit.String() {

				keysetResp := cashu.Keyset{
					Id:          mintKey[0].Id,
					Unit:        mintKey[0].Unit,
					InputFeePpk: mintKey[0].InputFeePpk,
					Keys:        make(map[string]string),
				}

				for _, keyset := range mintKey {
					keysetResp.Keys[strconv.FormatUint(keyset.Amount, 10)] = hex.EncodeToString(keyset.PrivKey.PubKey().SerializeCompressed())
				}

				keys = append(keys, keysetResp)
			}

		}
	}
	return keys, nil
}

// gets all keys from the signer
func (l *Signer) GetKeys() (GetKeysetsResponse, error) {
	var response GetKeysetsResponse
	seeds, err := l.db.GetAllSeeds()
	if err != nil {
		return response, fmt.Errorf(" l.db.GetAllSeeds(). %w", err)
	}
	for _, seed := range seeds {
		response.Keysets = append(response.Keysets, cashu.BasicKeysetResponse{Id: seed.Id, Unit: seed.Unit, Active: seed.Active, InputFeePpk: seed.InputFeePpk})
	}
	return response, nil
}

func (l *Signer) getSignerPrivateKey() (*secp256k1.PrivateKey, error) {
	mint_privkey := os.Getenv("MINT_PRIVATE_KEY")
	if mint_privkey == "" {
		return nil, fmt.Errorf(`os.Getenv("MINT_PRIVATE_KEY").`)
	}

	decodedPrivKey, err := hex.DecodeString(mint_privkey)
	if err != nil {
		return nil, fmt.Errorf(`hex.DecodeString(mint_privkey). %w`, err)
	}
	mintKey := secp256k1.PrivKeyFromBytes(decodedPrivKey)

	return mintKey, nil
}
func (l *Signer) createNewSeed(mintPrivateKey *bip32.Key, unit cashu.Unit, version int, fee uint) (cashu.Seed, error) {
	// rotate one level up
	newSeed := cashu.Seed{
		CreatedAt:   time.Now().Unix(),
		Active:      true,
		Version:     version,
		Unit:        unit.String(),
		InputFeePpk: fee,
	}

	keyset, err := DeriveKeyset(mintPrivateKey, newSeed)

	if err != nil {
		return newSeed, fmt.Errorf("DeriveKeyset(mintPrivateKey, newSeed) %w", err)
	}

	newSeedId, err := cashu.DeriveKeysetId(keyset)
	if err != nil {
		return newSeed, fmt.Errorf("cashu.DeriveKeysetId(keyset) %w", err)
	}

	newSeed.Id = newSeedId
	return newSeed, nil

}

func (l *Signer) RotateKeyset(unit cashu.Unit, fee uint) error {
	tx, err := l.db.Db.Begin()
	if err != nil {
		return fmt.Errorf("l.db.GetTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// get current highest seed version
	var highestSeed cashu.Seed = cashu.Seed{Version: 0}
	seeds, err := l.db.GetSeedsByUnit(tx, unit)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("database.GetSeedsByUnit(tx, unit). %w", err)

		}
	}
	for i, seed := range seeds {
		if highestSeed.Version < seed.Version {
			highestSeed = seed
		}

		seeds[i].Active = false
	}

	mintPrivateKey, err := l.getSignerPrivateKey()
	if err != nil {
		return fmt.Errorf(`l.getSignerPrivateKey() %w`, err)
	}

	signerMasterKey, err := bip32.NewMasterKey(mintPrivateKey.Serialize())
	if err != nil {
		return fmt.Errorf(" bip32.NewMasterKey(mintPrivateKey.Serialize()). %w", err)
	}

	// Create New seed with one higher version
	newSeed, err := l.createNewSeed(signerMasterKey, unit, highestSeed.Version+1, fee)

	if err != nil {
		return fmt.Errorf(`l.createNewSeed(signerMasterKey, unit, highestSeed.Version+1, fee) %w`, err)
	}

	// add new key to db
	err = l.db.SaveNewSeed(tx, newSeed)
	if err != nil {
		return fmt.Errorf(`l.db.SaveNewSeed(tx, newSeed). %w`, err)
	}

	// only need to update if there are any previous seeds
	if len(seeds) > 0 {
		err = l.db.UpdateSeedsActiveStatus(tx, seeds)
		if err != nil {
			return fmt.Errorf(`l.db.UpdateSeedsActiveStatus(tx, seeds). %w`, err)
		}
	}

	seeds = append(seeds, newSeed)

	keysets, activeKeysets, err := GetKeysetsFromSeeds(seeds, signerMasterKey)
	if err != nil {
		return fmt.Errorf(`m.DeriveKeysetFromSeeds(seeds, parsedPrivateKey). %w`, err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf(`tx.Commit(). %w`, err)
	}

	l.keysets = keysets
	l.activeKeysets = activeKeysets

	signerMasterKey = nil
	return nil
}

func (l *Signer) signBlindMessage(k *secp256k1.PrivateKey, message cashu.BlindedMessage) (cashu.BlindSignature, error) {
	var blindSignature cashu.BlindSignature

	decodedBlindFactor, err := hex.DecodeString(message.B_)

	if err != nil {
		return blindSignature, fmt.Errorf("DecodeString: %w", err)
	}

	B_, err := secp256k1.ParsePubKey(decodedBlindFactor)

	if err != nil {
		return blindSignature, fmt.Errorf("ParsePubKey: %w", err)
	}

	C_ := crypto.SignBlindedMessage(B_, k)

	blindSig := cashu.BlindSignature{
		Amount: message.Amount,
		Id:     message.Id,
		C_:     hex.EncodeToString(C_.SerializeCompressed()),
	}

	err = blindSig.GenerateDLEQ(B_, k)

	if err != nil {
		return blindSig, fmt.Errorf("blindSig.GenerateDLEQ: %w", err)
	}

	return blindSig, nil
}

func (l *Signer) SignBlindMessages(messages []cashu.BlindedMessage) ([]cashu.BlindSignature, []cashu.RecoverSigDB, error) {
	var blindedSignatures []cashu.BlindSignature
	var recoverSigDB []cashu.RecoverSigDB

	for _, output := range messages {
		correctKeyset := l.activeKeysets[output.Id][output.Amount]

		if correctKeyset.PrivKey == nil || !correctKeyset.Active {
			return nil, nil, cashu.UsingInactiveKeyset
		}

		blindSignature, err := output.GenerateBlindSignature(correctKeyset.PrivKey)

		recoverySig := cashu.RecoverSigDB{
			Amount:    output.Amount,
			Id:        output.Id,
			C_:        blindSignature.C_,
			B_:        output.B_,
			Dleq:      blindSignature.Dleq,
			CreatedAt: time.Now().Unix(),
		}

		if err != nil {
			err = fmt.Errorf("GenerateBlindSignature: %w %w", cashu.ErrInvalidBlindMessage, err)
			return nil, nil, err
		}

		blindedSignatures = append(blindedSignatures, blindSignature)
		recoverSigDB = append(recoverSigDB, recoverySig)

	}
	return blindedSignatures, recoverSigDB, nil

}

func (l *Signer) VerifyProofs(proofs []cashu.Proof, blindMessages []cashu.BlindedMessage) error {
	checkOutputs := false

	pubkeysFromProofs := make(map[*btcec.PublicKey]bool)

	for _, proof := range proofs {
		err := l.validateProof(proof, &checkOutputs, &pubkeysFromProofs)
		if err != nil {
			return fmt.Errorf("l.validateProof(proof, unit, &checkOutputs, &pubkeysFromProofs): %w", err)
		}
	}
	// if any sig allis present all outputs also need to be check with the pubkeys from the proofs
	if checkOutputs {
		for _, blindMessage := range blindMessages {

			err := blindMessage.VerifyBlindMessageSignature(pubkeysFromProofs)
			if err != nil {
				return fmt.Errorf("blindMessage.VerifyBlindMessageSignature: %w", err)
			}

		}
	}

	return nil
}

func (l *Signer) validateProof(proof cashu.Proof, checkOutputs *bool, pubkeysFromProofs *map[*btcec.PublicKey]bool) error {
	var keysetToUse cashu.MintKey

	keysets, exists := l.keysets[proof.Id]
	if !exists {
		return cashu.ErrKeysetForProofNotFound
	}

	for _, keyset := range keysets {
		if keyset.Amount == proof.Amount && keyset.Id == proof.Id {
			keysetToUse = keyset
			break
		}
	}

	// check if keysetToUse is not assigned
	if keysetToUse.Id == "" {
		return cashu.ErrKeysetForProofNotFound
	}

	// check if a proof is locked to a spend condition and verifies it
	isProofLocked, spendCondition, witness, err := proof.IsProofSpendConditioned(checkOutputs)

	if err != nil {
		return fmt.Errorf("proof.IsProofSpendConditioned(): %w %w", err, cashu.ErrInvalidProof)
	}

	if isProofLocked {
		ok, err := proof.VerifyWitness(spendCondition, witness, pubkeysFromProofs)

		if err != nil {
			return fmt.Errorf("proof.VerifyWitnessSig(): %w", err)
		}

		if !ok {
			return cashu.ErrInvalidProof
		}
	}
	parsedBlinding, err := hex.DecodeString(proof.C)
	if err != nil {
		return fmt.Errorf("hex.DecodeString: %w %w", err, cashu.ErrInvalidProof)
	}
	pubkey, err := secp256k1.ParsePubKey(parsedBlinding)
	if err != nil {
		return fmt.Errorf("secp256k1.ParsePubKey: %w %w", err, cashu.ErrInvalidProof)
	}
	verified := crypto.Verify(proof.Secret, keysetToUse.PrivKey, pubkey)
	if !verified {
		return cashu.ErrInvalidProof
	}

	return nil

}
func (l *Signer) GetSignerPubkey() (string, error) {

	mintPrivateKey, err := l.getSignerPrivateKey()
	if err != nil {
		return "", fmt.Errorf(`l.getSignerPrivateKey() %w`, err)
	}

	return hex.EncodeToString(mintPrivateKey.PubKey().SerializeCompressed()), nil
}

package signer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"nutmix_remote_signer/database"
	"os"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	goNutsCashu "github.com/elnosh/gonuts/cashu"
	"github.com/elnosh/gonuts/cashu/nuts/nut01"
	"github.com/elnosh/gonuts/cashu/nuts/nut02"
	"github.com/elnosh/gonuts/cashu/nuts/nut10"
	"github.com/elnosh/gonuts/cashu/nuts/nut11"
	"github.com/elnosh/gonuts/cashu/nuts/nut14"
	"github.com/elnosh/gonuts/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/lescuer97/nutmix/api/cashu"
	"github.com/tyler-smith/go-bip32"
)

var ErrNoKeysetFound = errors.New("No keyset found")

type Signer struct {
	keysets       map[string]crypto.MintKeyset
	activeKeysets map[string]crypto.MintKeyset
	db            database.SqliteDB
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
	// keysets[0]

	signer.keysets = keysets
	signer.activeKeysets = activeKeysets

	masterKey = nil
	return signer, nil

}

func (l *Signer) GetKeysById(id string) (nut01.GetKeysResponse, error) {

	val, exists := l.keysets[id]
	if exists {

		return OrderKeysetByUnit([]crypto.MintKeyset{val}), nil

	}
	return nut01.GetKeysResponse{}, ErrNoKeysetFound
}

func (l *Signer) GetActiveKeys() (nut01.GetKeysResponse, error) {

	// l.keysets[0].
	// DeriveKeyset()
	// convert map to slice
	var keys []crypto.MintKeyset
	for _, keyset := range l.activeKeysets {
		keys = append(keys, keyset)
	}

	// sort.Slice(keys, func(i, j int) bool {
	// 	return keys[i].Amount < keys[j].Amount
	// })

	return OrderKeysetByUnit(keys), nil
}

func (l *Signer) GetKeysets() (nut02.GetKeysetsResponse, error) {
	var response nut02.GetKeysetsResponse
	seeds, err := l.db.GetAllSeeds()
	if err != nil {
		return response, fmt.Errorf(" l.db.GetAllSeeds(). %w", err)
	}
	for _, seed := range seeds {
		response.Keysets = append(response.Keysets, nut02.Keyset{Id: seed.Id, Unit: seed.Unit, Active: seed.Active, InputFeePpk: seed.InputFeePpk})
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

	if keyset.Id == "" {
		panic("keyset id was not generated")
	}

	newSeed.Id = keyset.Id
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

func (l *Signer) SignBlindMessages(messages goNutsCashu.BlindedMessages) (goNutsCashu.BlindedSignatures, error) {
	var blindedSignatures goNutsCashu.BlindedSignatures

	for _, output := range messages {
		correctKeyset := l.activeKeysets[output.Id].Keys[output.Amount]

		if correctKeyset.PrivateKey == nil || !l.activeKeysets[output.Id].Active {
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
		if err != nil {
			err = fmt.Errorf("GenerateBlindSignature: %w %w", cashu.ErrInvalidBlindMessage, err)
			return nil, err
		}

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
	checkOutputs := false

	pubkeysFromProofs := make(map[*btcec.PublicKey]bool)

	for _, proof := range proofs {
		err := l.validateProof(proof, &checkOutputs, &pubkeysFromProofs)
		if err != nil {
			return fmt.Errorf("l.validateProof(proof, unit, &checkOutputs, &pubkeysFromProofs): %w", err)
		}
	}
	// if any sig allis present all outputs also need to be check with the pubkeys from the proofs
	// if checkOutputs {
	// 	for _, blindMessage := range blindMessages {
	//
	// 		err := blindMessage.VerifyBlindMessageSignature(pubkeysFromProofs)
	// 		if err != nil {
	// 			return fmt.Errorf("blindMessage.VerifyBlindMessageSignature: %w", err)
	// 		}
	//
	// 	}
	// }

	return nil
}

func (l *Signer) validateProof(proof goNutsCashu.Proof, checkOutputs *bool, pubkeysFromProofs *map[*btcec.PublicKey]bool) error {
	keysets, exists := l.keysets[proof.Id]
	if !exists {
		return cashu.ErrKeysetForProofNotFound
	}

	keypair := keysets.Keys[proof.Amount]
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

	knownSecret, err := nut10.DeserializeSecret(proof.Secret)
	if err != nil {
		err = fmt.Errorf("nut10.DeserializeSecret(proof.Secret)): %w %w", cashu.ErrInvalidProof, err)
		return err
	}

	if knownSecret.Kind != nut10.AnyoneCanSpend {
		switch knownSecret.Kind {
		case nut10.P2PK:
			err := verifyP2PKLockedProof(proof, knownSecret)
			if err != nil {
				return fmt.Errorf("l.VerifyP2PK(proof, knownSecret): %w %w", cashu.ErrInvalidProof, err)
			}

		case nut10.HTLC:
			err := verifyHTLCProof(proof, knownSecret)
			if err != nil {
				return fmt.Errorf("verifyHTLCProof(proof, knownSecret): %w %w", cashu.ErrInvalidProof, err)
			}
		}

	}

	return nil
}

// returns serialized compressed public key
func (l *Signer) GetSignerPubkey() ([]byte, error) {

	mintPrivateKey, err := l.getSignerPrivateKey()
	if err != nil {
		return []byte{}, fmt.Errorf(`l.getSignerPrivateKey() %w`, err)
	}

	return mintPrivateKey.PubKey().SerializeCompressed(), nil
}
func verifyP2PKLockedProof(proof goNutsCashu.Proof, proofSecret nut10.WellKnownSecret) error {
	var p2pkWitness nut11.P2PKWitness
	json.Unmarshal([]byte(proof.Witness), &p2pkWitness)

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
	json.Unmarshal([]byte(proof.Witness), &htlcWitness)

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

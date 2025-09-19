package signer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"nutmix_remote_signer/database"
	"strconv"
	"sync"
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
	"github.com/lescuer97/bip85"
	"github.com/lescuer97/nutmix/api/cashu"
)

type KeysetGenerationIndexes map[string]map[uint64]int

type KeysManager struct {
	keys map[string]KeysetStore
	sync.RWMutex
}

func (s *KeysManager) AddAccount(id string, store KeysetStore) error {
	s.Lock()
	defer s.Unlock()

	_, ok := s.keys[id]
	if ok {
		return fmt.Errorf("This account already exists")
	}
	s.keys[id] = store

	return nil
}
func (s *KeysManager) ChangeAccount(id string, store KeysetStore) error {
	s.Lock()
	defer s.Unlock()

	_, ok := s.keys[id]
	if !ok {
		return fmt.Errorf("There are no accounts for this id")
	}
	s.keys[id] = store

	return nil
}
func (s *KeysManager) GetAccount(id string) (KeysetStore, error) {
	s.Lock()
	defer s.Unlock()

	store, ok := s.keys[id]
	if !ok {
		return KeysetStore{}, fmt.Errorf("There are no accounts for this id")
	}
	return store, nil
}

type MultiAccountSigner struct {
	keysManager        KeysManager
	db             database.SqliteDB
	expirationTime time.Time
}

type SignerInfo struct {
	AccountId  string
	Derivation uint32
}

func SetupLocalSigner(db database.SqliteDB, config Config) (*MultiAccountSigner, error) {
	signer := MultiAccountSigner{
		db: db,
		keysManager: KeysManager{
			keys: make(map[string]KeysetStore),
		},
		expirationTime: config.ExpireTime,
	}

	slog.Info("Trying to get the Mint key")
	bip85Master, err := signer.getMasterBip85Key()
	defer func() {
		bip85Master = nil
	}()
	if err != nil {
		return &signer, fmt.Errorf("l.getMasterBip85Key(). %w", err)
	}

	slog.Debug("Getting all account with seeds")
	accountBySeeds, err := signer.db.GetAccountsWithSeeds()
	if err != nil {
		return &signer, fmt.Errorf("signer.db.GetAccountsWithSeeds(). %w", err)
	}

	_, err = secp256k1.ParsePubKey(bip85Master.GetMasterKey().PublicKey().Key)
	if err != nil {
		log.Panicf("Could not get the public key for the signer master key")
	}

	// signer.signers = make(map[string]KeysetStore)
	for i := range accountBySeeds {
		derivedSignerKey, err := signer.getDerivedMasterKey(bip85Master, accountBySeeds[i].Derivation)
		defer func() {
			derivedSignerKey = nil
		}()
		if err != nil {
			return &signer, fmt.Errorf("signer.getDerivedMasterKey(bip85Master, accountBySeeds[i].Derivation). %w", err)
		}

		if len(accountBySeeds[i].Seeds) == 0 {
			slog.Info("There are no seeds available. For signer", slog.String("signerId", accountBySeeds[i].Id))
			slog.Debug("Generating amounts for new seed")
			amounts := GetAmountsFromMaxOrder(DefaultMaxOrder)
			slog.Info("Creating a new seed")
			newSeed, err := signer.createNewSeed(derivedSignerKey, cashu.Sat, 1, 0, amounts, config.ExpireTime)
			if err != nil {
				return &signer, fmt.Errorf("signer.createNewSeed(masterKey, 1, 0). %w", err)
			}

			newSeed.AccountId = accountBySeeds[i].Id
			tx, err := db.Db.Begin()
			if err != nil {
				return &signer, fmt.Errorf("l.db.GetTx(ctx). %w", err)
			}
			defer tx.Rollback()

			slog.Info("Saving seed for to the database")
			err = db.SaveNewSeed(tx, newSeed)
			if err != nil {
				return &signer, fmt.Errorf("db.SaveNewSeeds([]cashu.Seed{newSeed}). %w", err)
			}
			err = tx.Commit()
			if err != nil {
				return &signer, fmt.Errorf(`tx.Commit(). %w`, err)
			}

			accountBySeeds[i].Seeds = append(accountBySeeds[i].Seeds, newSeed)
		}

		store := NewKeysetStore()
		keysets, activeKeysets, err := GetKeysetsFromSeeds(accountBySeeds[i].Seeds, derivedSignerKey)
		if err != nil {
			return &signer, fmt.Errorf(`signer.GetKeysetsFromSeeds(seeds, masterKey). %w`, err)
		}
		// account := signer.signers[accountBySeeds[i].Id]
		store.SetAll(keysets, activeKeysets)
		store.SetIndexesFromSeeds(accountBySeeds[i].Seeds)

		pubkey, err := derivedSignerKey.ECPubKey()
		if err != nil {
			return &signer, fmt.Errorf(`derivedSignerKey.ECPubKey(). %w`, err)
		}
		store.SetPubkey(pubkey)
		err = signer.keysManager.AddAccount(accountBySeeds[i].Id, store)
		if err != nil {
			return &signer, fmt.Errorf(`signer.signers.AddAccount(accountBySeeds[i].Id, store). %w`, err)
		}

	}
	return &signer, nil
}

func (l *MultiAccountSigner) GetKeysets(signerInfo SignerInfo) ([]MintPublicKeyset, error) {
	response := []MintPublicKeyset{}
	signer, err := l.keysManager.GetAccount(signerInfo.AccountId)
	if err != nil {
		return nil, fmt.Errorf("Account does not exists")
	}
	for _, mintkey := range signer.keysets {
		response = append(response, mintkey)
	}

	return response, nil
}

func (l *MultiAccountSigner) getMasterBip85Key() (*bip85.Bip85, error) {
	seedFromDBUS, err := getNutmixSignerKey()
	defer func() {
		seedFromDBUS = ""
	}()
	if err != nil {
		return nil, fmt.Errorf("signer.getSignerPrivateKey(). %w", err)
	}

	bip85Key, err := bip85.NewBip85FromMnemonic(seedFromDBUS, "")
	if err != nil {
		return nil, fmt.Errorf("bip85.NewBip85FromBip32Key(privateKey). %w", err)
	}
	return bip85Key, nil
}

func (l *MultiAccountSigner) getDerivedMasterKey(bip85Key *bip85.Bip85, derivation uint32) (*hdkeychain.ExtendedKey, error) {
	derivedKey, err := bip85Key.DeriveToXpriv(derivation)
	defer func() {
		derivedKey = nil
	}()
	if err != nil {
		return nil, fmt.Errorf("bip85Key.DeriveToXpriv(signerInfo.derivation). %w", err)
	}

	derivedSignerKey, err := hdkeychain.NewMaster(derivedKey.Key, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("hdkeychain.NewMaster(derivedKey.Key, &chaincfg.MainNetParams). %w", err)
	}
	return derivedSignerKey, nil
}

func (l *MultiAccountSigner) createNewSeed(mintPrivateKey *hdkeychain.ExtendedKey, unit cashu.Unit, version uint64, fee uint, amounts []uint64, expiry_time time.Time) (database.Seed, error) {
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
		FinalExpiry: expiry_time,
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

func (l *MultiAccountSigner) RotateKeyset(signerInfo SignerInfo, unit cashu.Unit, fee uint64, amounts []uint64, expiry_time time.Time) (MintPublicKeyset, error) {
	slog.Info("Rotating keyset", slog.String("unit", unit.String()), slog.String("fee", strconv.FormatUint(uint64(fee), 10)))
	newKey := MintPublicKeyset{}

	tx, err := l.db.Db.Begin()
	if err != nil {
		return newKey, fmt.Errorf("l.db.GetTx(ctx). %w", err)
	}
	defer tx.Rollback()

	// get current highest seed version
	var highestSeed database.Seed = database.Seed{Version: 0}
	slog.Debug("Getting seed from unit", slog.String("unit", unit.String()))
	seeds, err := l.db.GetSeedsByAccountId(tx, signerInfo.AccountId)
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
	bip85Master, err := l.getMasterBip85Key()
	defer func() {
		bip85Master = nil
	}()
	if err != nil {
		return newKey, fmt.Errorf("l.getMasterBip85Key(). %w", err)
	}
	derivedSignerKey, err := l.getDerivedMasterKey(bip85Master, signerInfo.Derivation)
	defer func() {
		derivedSignerKey = nil
	}()
	if err != nil {
		return newKey, fmt.Errorf("l.getDerivedMasterKey(bip85Master, signerInfo.Derivation). %w", err)
	}

	// Create New seed with one higher version
	newSeed, err := l.createNewSeed(derivedSignerKey, unit, highestSeed.Version+1, uint(fee), amounts, expiry_time)
	if err != nil {
		return newKey, fmt.Errorf(`l.createNewSeed(signerMasterKey, unit, highestSeed.Version+1, fee) %w`, err)
	}
	newSeed.AccountId = signerInfo.AccountId

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

	keysets, activeKeysets, err := GetKeysetsFromSeeds(seeds, derivedSignerKey)
	if err != nil {
		return newKey, fmt.Errorf(`m.DeriveKeysetFromSeeds(seeds, parsedPrivateKey). %w`, err)
	}

	err = tx.Commit()
	if err != nil {
		return newKey, fmt.Errorf(`tx.Commit(). %w`, err)
	}

	account, err := l.keysManager.GetAccount(signerInfo.AccountId)
	if err != nil {
		return newKey, fmt.Errorf(`account signer is non existent. %w`, err)
	}
	account.SetAll(keysets, activeKeysets)
	account.SetIndexesFromSeeds(seeds)

	err = l.keysManager.ChangeAccount(signerInfo.AccountId, account)
	if err != nil {
		return newKey, fmt.Errorf(`could not add account. %w`, err)
	}

	derivedSignerKey = nil
	return func() (MintPublicKeyset, error) {
		ks, ok := account.GetKeysetById(newSeed.Id)
		if !ok {
			return MintPublicKeyset{}, fmt.Errorf("keyset not found after rotation: %s", newSeed.Id)
		}
		return ks, nil
	}()
}

func (l *MultiAccountSigner) SignBlindMessages(messages goNutsCashu.BlindedMessages, signerInfo SignerInfo) (goNutsCashu.BlindedSignatures, error) {
	var blindedSignatures goNutsCashu.BlindedSignatures

	indexesForGeneration := make(KeysetGenerationIndexes)

	slog.Debug("Finding account from the signer")
	signer, err := l.keysManager.GetAccount(signerInfo.AccountId)
	if err != nil {
		return nil, fmt.Errorf("Account does not exists")
	}
	slog.Debug("Finding what amounts we need to create private keys for")
	// get generation index from the stored index in the signer
	for _, output := range messages {
		keyset, keysetExits := signer.GetIndex(output.Id)
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

	keysets, err := l.GenerateMintKeysFromPublicKeysets(indexesForGeneration, signerInfo)
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

func (l *MultiAccountSigner) VerifyProofs(signerInfo SignerInfo, proofs goNutsCashu.Proofs, blindMessages goNutsCashu.BlindedMessages) error {
	indexesForGeneration := make(KeysetGenerationIndexes)

	slog.Debug("Finding what amounts we need to create private keys for")
	signer, err := l.keysManager.GetAccount(signerInfo.AccountId)
	if err != nil {
		return fmt.Errorf("Account does not exists")
	}
	// get index of amounts to use for generation
	for _, proof := range proofs {
		keyset, keysetExits := signer.GetIndex(proof.Id)
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

	keysets, err := l.GenerateMintKeysFromPublicKeysets(indexesForGeneration, signerInfo)
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

func (l *MultiAccountSigner) validateProof(keysets map[string]MintKeyset, proof goNutsCashu.Proof) error {
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
func (l *MultiAccountSigner) GetSignerPubkey(signerInfo SignerInfo) ([]byte, error) {
	signer, err := l.keysManager.GetAccount(signerInfo.AccountId)
	if err != nil {
		return nil, fmt.Errorf("Account does not exists")
	}
	return signer.pubkey.SerializeCompressed(), nil
}

func (l *MultiAccountSigner) AddKeysToSignerFromAccount(accountId string, derivation uint32) error {
	slog.Info("Trying to get the Mint key")
	bip85Master, err := l.getMasterBip85Key()
	defer func() {
		bip85Master = nil
	}()
	if err != nil {
		return fmt.Errorf("l.getMasterBip85Key(). %w", err)
	}
	tx, err := l.db.Db.Begin()
	if err != nil {
		return fmt.Errorf("l.getMasterBip85Key(). %w", err)
	}
	defer tx.Rollback()

	slog.Debug("Getting all account with seeds")
	seeds, err := l.db.GetSeedsByAccountId(tx, accountId)
	if err != nil {
		return fmt.Errorf("signer.db.GetAccountsWithSeeds(). %w", err)
	}

	_, err = secp256k1.ParsePubKey(bip85Master.GetMasterKey().PublicKey().Key)
	if err != nil {
		log.Panicf("Could not get the public key for the signer master key")
	}

	derivedSignerKey, err := l.getDerivedMasterKey(bip85Master, derivation)
	defer func() {
		derivedSignerKey = nil
	}()
	if err != nil {
		return fmt.Errorf("signer.getDerivedMasterKey(bip85Master, accountBySeeds[i].Derivation). %w", err)
	}

	if len(seeds) == 0 {
		slog.Info("There are no seeds available. For signer", slog.String("signerId", accountId))
		slog.Debug("Generating amounts for new seed")
		amounts := GetAmountsFromMaxOrder(DefaultMaxOrder)
		slog.Info("Creating a new seed")
		newSeed, err := l.createNewSeed(derivedSignerKey, cashu.Sat, 1, 0, amounts, l.expirationTime)
		if err != nil {
			return fmt.Errorf("l.createNewSeed(derivedSignerKey, cashu.Sat, 1, 0, amounts, l.expirationTime). %w", err)
		}
		newSeed.AccountId = accountId
		slog.Info("Saving seed for to the database")
		err = l.db.SaveNewSeed(tx, newSeed)
		if err != nil {
			return fmt.Errorf("db.SaveNewSeeds([]cashu.Seed{newSeed}). %w", err)
		}
		err = tx.Commit()
		if err != nil {
			return fmt.Errorf(`tx.Commit(). %w`, err)
		}

		seeds = append(seeds, newSeed)
	}
	store := NewKeysetStore()
	keysets, activeKeysets, err := GetKeysetsFromSeeds(seeds, derivedSignerKey)
	if err != nil {
		return fmt.Errorf(`signer.GetKeysetsFromSeeds(seeds, masterKey). %w`, err)
	}
	store.SetAll(keysets, activeKeysets)
	store.SetIndexesFromSeeds(seeds)

	pubkey, err := derivedSignerKey.ECPubKey()
	if err != nil {
		return fmt.Errorf(`derivedSignerKey.ECPubKey(). %w`, err)
	}
	store.SetPubkey(pubkey)
	err = l.keysManager.AddAccount(accountId, store)
	if err != nil {
		return fmt.Errorf(`signer.signers.AddAccount(accountBySeeds[i].Id, store). %w`, err)
	}
	return nil
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

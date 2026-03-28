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

type Signer struct {
	accounts *AccountsStore
	db       database.SqliteDB
}

func SetupLocalSigner(db database.SqliteDB, config Config) (*Signer, error) {
	signer := &Signer{
		db:       db,
		accounts: NewAccountsStore(),
	}

	if err := SetupKeychain(); err != nil {
		return nil, fmt.Errorf("SetupKeychain(): %w", err)
	}

	slog.Info("Trying to get the Mint key")
	_, err := getNutmixSignerKey()
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			slog.Warn("seedphrase was not found in store. looking for one or generating one.", slog.Any("error", err))
			if _, err = signer.findOrGenerateANewSeedphrase(); err != nil {
				return nil, fmt.Errorf("signer.findOrGenerateANewSeedphrase(): %w", err)
			}
		} else {
			return nil, fmt.Errorf("signer.getSignerPrivateKey(): %w", err)
		}
	}

	masterMnemonic, err := getMasterMnemonic()
	if err != nil {
		return nil, fmt.Errorf("getMasterMnemonic(): %w", err)
	}

	accountsWithSeeds, err := signer.db.GetAccountsWithSeeds()
	if err != nil {
		return nil, fmt.Errorf("signer.db.GetAccountsWithSeeds(): %w", err)
	}

	for _, accountWithSeeds := range accountsWithSeeds {
		if err := signer.loadAccount(accountWithSeeds.Account, accountWithSeeds.Seeds, masterMnemonic); err != nil {
			return nil, fmt.Errorf("signer.loadAccount(%s): %w", accountWithSeeds.Account.Id, err)
		}
	}

	if config.AutoRotate && config.ExpireTime != nil {
		slog.Debug("auto rotate activated starting watcher")
		go signer.startWatcher(config.ExpireTime)
	}

	return signer, nil
}

func (s *Signer) loadAccount(account database.Account, seeds []database.Seed, mnemonic string) error {
	accountKey, err := s.getAccountMasterKeyFromAccount(account, mnemonic)
	if err != nil {
		return fmt.Errorf("s.getAccountMasterKeyFromAccount(account): %w", err)
	}
	defer func() {
		accountKey = nil
	}()

	if len(seeds) == 0 {
		amounts := GetAmountsFromMaxOrder(DefaultMaxOrder)
		newSeed, err := s.createNewSeed(account.Id, accountKey, cashu.Sat, 0, 0, amounts, nil)
		if err != nil {
			return fmt.Errorf("s.createNewSeed(account.Id, ...): %w", err)
		}

		tx, err := s.db.Db.Begin()
		if err != nil {
			return fmt.Errorf("s.db.Db.Begin(): %w", err)
		}
		defer func() {
			_ = tx.Rollback()
		}()
		if err := s.db.SaveNewSeed(tx, newSeed); err != nil {
			return fmt.Errorf("s.db.SaveNewSeed(tx, newSeed): %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("tx.Commit(): %w", err)
		}
		seeds = append(seeds, newSeed)
	}

	store, err := s.buildAccountStore(accountKey, seeds)
	if err != nil {
		return err
	}
	s.accounts.SetAccount(account.Id, store)
	return nil
}

func (s *Signer) buildAccountStore(accountKey *hdkeychain.ExtendedKey, seeds []database.Seed) (*KeysetStore, error) {
	keysets, activeKeysets, err := GetKeysetsFromSeeds(seeds, accountKey)
	if err != nil {
		return nil, fmt.Errorf("GetKeysetsFromSeeds(seeds, accountKey): %w", err)
	}
	store := NewKeysetStore()
	store.SetAll(keysets, activeKeysets)
	store.SetIndexesFromSeeds(seeds)
	pubkey, err := accountKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("accountKey.ECPubKey(): %w", err)
	}
	store.SetPubkey(pubkey)
	return store, nil
}

func (s *Signer) getAccountMasterKey(signerInfo SignerInfo) (*hdkeychain.ExtendedKey, error) {
	account, err := s.db.GetAccountByID(signerInfo.AccountID)
	if err != nil {
		return nil, fmt.Errorf("s.db.GetAccountByID(%s): %w", signerInfo.AccountID, err)
	}
	if signerInfo.Derivation != 0 && signerInfo.Derivation != account.Derivation {
		return nil, fmt.Errorf("signer derivation mismatch for account %s", signerInfo.AccountID)
	}
	return s.getAccountMasterKeyFromAccount(*account, "")
}

func (s *Signer) getAccountMasterKeyFromAccount(account database.Account, mnemonic string) (*hdkeychain.ExtendedKey, error) {
	if account.Id == database.DefaultAccountID {
		return GetMasterKey()
	}
	if mnemonic == "" {
		var err error
		mnemonic, err = getMasterMnemonic()
		if err != nil {
			return nil, fmt.Errorf("getMasterMnemonic(): %w", err)
		}
	}
	bip85Key, err := getMasterBIP85Key(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("getMasterBIP85Key(): %w", err)
	}
	return getDerivedAccountKey(bip85Key, account.Derivation)
}

func (s *Signer) startWatcher(expiryTime *time.Time) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		accounts, err := s.db.GetAllAccounts()
		if err != nil {
			slog.Error("could not load accounts for auto-rotate", slog.String("err", err.Error()))
			continue
		}
		now := time.Now()
		for _, account := range accounts {
			store, err := s.accounts.GetAccount(account.Id)
			if err != nil {
				continue
			}
			for _, ks := range store.GetActiveKeysetsCopy() {
				if ks.FinalExpiry == nil || ks.FinalExpiry.After(now) {
					continue
				}
				unit, err := cashu.UnitFromString(strings.ToLower(ks.Unit))
				if err != nil {
					slog.Error("Could not parse unit for expired keyset", slog.String("unit", ks.Unit), slog.String("err", err.Error()))
					continue
				}
				amounts := make([]uint64, 0, len(ks.Keys))
				for amount := range ks.Keys {
					amounts = append(amounts, amount)
				}
				_, err = s.RotateKeyset(SignerInfo{AccountID: account.Id, Derivation: account.Derivation}, unit, uint64(ks.InputFeePpk), amounts, expiryTime)
				if err != nil {
					slog.Error("Auto-rotation failed", slog.String("account_id", account.Id), slog.String("unit", ks.Unit), slog.String("err", err.Error()))
				}
			}
		}
	}
}

func (s *Signer) GetKeysets(signerInfo SignerInfo) ([]MintPublicKeyset, error) {
	store, err := s.accounts.GetAccount(signerInfo.AccountID)
	if err != nil {
		return nil, err
	}
	return store.GetKeysetsList(), nil
}

func unitNormalization(unit string) string {
	unitStr := strings.TrimSpace(unit)
	unitStr = norm.NFC.String(unitStr)
	return strings.ToUpper(unitStr)
}

func (s *Signer) createNewSeed(accountID string, mintPrivateKey *hdkeychain.ExtendedKey, unit cashu.Unit, version uint64, fee uint, amounts []uint64, expiryTime *time.Time) (database.Seed, error) {
	slog.Info("Generating new seed", slog.String("account_id", accountID), slog.String("unit", unit.String()), slog.String("version", strconv.FormatInt(int64(version), 10)), slog.String("fee", strconv.FormatUint(uint64(fee), 10)))

	if unit == cashu.AUTH {
		amounts = []uint64{1}
	}

	newSeed := database.Seed{
		CreatedAt:      time.Now().Unix(),
		Active:         true,
		Version:        version,
		Unit:           unitNormalization(unit.String()),
		InputFeePpk:    fee,
		Legacy:         false,
		Amounts:        amounts,
		FinalExpiry:    expiryTime,
		Id:             "",
		AccountID:      accountID,
		DerivationPath: keyDerivation(uint(version), unit),
	}

	keyset, err := DeriveKeyset(mintPrivateKey, newSeed)
	if err != nil {
		return newSeed, fmt.Errorf("DeriveKeyset(mintPrivateKey, newSeed): %w", err)
	}
	if len(keyset.Id) == 0 {
		panic("keyset id was not generated")
	}

	existing := []MintPublicKeyset{}
	if store, err := s.accounts.GetAccount(accountID); err == nil {
		existing = store.GetKeysetsList()
	}
	if err := unitStringCollissionCheck(existing, newSeed.Unit); err != nil {
		return newSeed, fmt.Errorf("unitStringCollissionCheck(existing, newSeed.Unit): %w", err)
	}

	newSeed.Id = hex.EncodeToString(keyset.Id)
	return newSeed, nil
}

func (s *Signer) RotateKeyset(signerInfo SignerInfo, unit cashu.Unit, fee uint64, amounts []uint64, expiryTime *time.Time) (MintPublicKeyset, error) {
	newKey := MintPublicKeyset{}
	tx, err := s.db.Db.Begin()
	if err != nil {
		return newKey, fmt.Errorf("s.db.Db.Begin(): %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	seeds, err := s.db.GetSeedsByAccountAndUnit(tx, signerInfo.AccountID, unit)
	if err != nil {
		return newKey, fmt.Errorf("s.db.GetSeedsByAccountAndUnit(tx, signerInfo.AccountID, unit): %w", err)
	}
	highestSeedVersion := uint64(0)
	for i, seed := range seeds {
		if highestSeedVersion <= seed.Version {
			highestSeedVersion = seed.Version + 1
		}
		seeds[i].Active = false
	}

	accountKey, err := s.getAccountMasterKey(signerInfo)
	if err != nil {
		return newKey, fmt.Errorf("s.getAccountMasterKey(signerInfo): %w", err)
	}
	defer func() {
		accountKey = nil
	}()

	newSeed, err := s.createNewSeed(signerInfo.AccountID, accountKey, unit, highestSeedVersion, uint(fee), amounts, expiryTime)
	if err != nil {
		return newKey, fmt.Errorf("s.createNewSeed(...): %w", err)
	}
	if err := s.db.SaveNewSeed(tx, newSeed); err != nil {
		return newKey, fmt.Errorf("s.db.SaveNewSeed(tx, newSeed): %w", err)
	}
	if len(seeds) > 0 {
		if err := s.db.UpdateSeedsActiveStatus(tx, seeds); err != nil {
			return newKey, fmt.Errorf("s.db.UpdateSeedsActiveStatus(tx, seeds): %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return newKey, fmt.Errorf("tx.Commit(): %w", err)
	}

	seeds = append(seeds, newSeed)
	store, err := s.buildAccountStore(accountKey, seeds)
	if err != nil {
		return newKey, err
	}
	s.accounts.SetAccount(signerInfo.AccountID, store)

	ks, ok := store.GetKeysetById(newSeed.Id)
	if !ok {
		return MintPublicKeyset{}, fmt.Errorf("keyset not found after rotation: %s", newSeed.Id)
	}
	return ks, nil
}

func (s *Signer) SignBlindMessages(messages goNutsCashu.BlindedMessages, signerInfo SignerInfo) (goNutsCashu.BlindedSignatures, error) {
	var blindedSignatures goNutsCashu.BlindedSignatures
	indexesForGeneration := make(KeysetGenerationIndexes)
	store, err := s.accounts.GetAccount(signerInfo.AccountID)
	if err != nil {
		return nil, err
	}

	for _, output := range messages {
		keyset, exists := store.GetIndex(output.Id)
		if !exists {
			return nil, fmt.Errorf("keyset does not exist: Id: %+v", output.Id)
		}
		if _, ok := indexesForGeneration[output.Id]; !ok {
			indexesForGeneration[output.Id] = make(map[uint64]int)
		}
		i, amountExists := keyset[output.Amount]
		if !amountExists {
			return nil, fmt.Errorf("no index was found for this amount: %+v", output.Amount)
		}
		indexesForGeneration[output.Id][output.Amount] = i
	}

	keysets, err := s.GenerateMintKeysFromPublicKeysets(indexesForGeneration, signerInfo)
	if err != nil {
		return nil, fmt.Errorf("s.GenerateMintKeysFromPublicKeysets(indexesForGeneration, signerInfo): %w", err)
	}

	for _, output := range messages {
		correctKeyset := keysets[output.Id].Keys[output.Amount]
		if correctKeyset.PrivateKey == nil || !keysets[output.Id].Active {
			return nil, cashu.UsingInactiveKeyset
		}

		pubkeyBytes, err := hex.DecodeString(output.B_)
		if err != nil {
			return nil, fmt.Errorf("hex.DecodeString(output.B_): %w %w", cashu.ErrInvalidBlindMessage, err)
		}
		blindedMsg, err := secp256k1.ParsePubKey(pubkeyBytes)
		if err != nil {
			return nil, fmt.Errorf("secp256k1.ParsePubKey(serializedPubkey): %w %w", cashu.ErrInvalidBlindMessage, err)
		}

		sig := crypto.SignBlindedMessage(blindedMsg, correctKeyset.PrivateKey)
		E, S := crypto.GenerateDLEQ(correctKeyset.PrivateKey, blindedMsg, sig)
		dleq := goNutsCashu.DLEQProof{E: hex.EncodeToString(E.Serialize()), S: hex.EncodeToString(S.Serialize()), R: ""}

		blindedSignatures = append(blindedSignatures, goNutsCashu.BlindedSignature{
			Amount: output.Amount,
			Id:     output.Id,
			C_:     hex.EncodeToString(sig.SerializeCompressed()),
			DLEQ:   &dleq,
		})
	}

	return blindedSignatures, nil
}

func (s *Signer) VerifyProofs(signerInfo SignerInfo, proofs goNutsCashu.Proofs, blindMessages goNutsCashu.BlindedMessages) error {
	indexesForGeneration := make(KeysetGenerationIndexes)
	store, err := s.accounts.GetAccount(signerInfo.AccountID)
	if err != nil {
		return err
	}

	for _, proof := range proofs {
		keyset, exists := store.GetIndex(proof.Id)
		if !exists {
			return fmt.Errorf("keyset does not exist: Id: %+v", proof.Id)
		}
		if _, ok := indexesForGeneration[proof.Id]; !ok {
			indexesForGeneration[proof.Id] = make(map[uint64]int)
		}
		i, amountExists := keyset[proof.Amount]
		if !amountExists {
			return fmt.Errorf("no index was found for this amount: %+v", proof.Amount)
		}
		indexesForGeneration[proof.Id][proof.Amount] = i
	}

	keysets, err := s.GenerateMintKeysFromPublicKeysets(indexesForGeneration, signerInfo)
	if err != nil {
		return fmt.Errorf("s.GenerateMintKeysFromPublicKeysets(indexesForGeneration, signerInfo): %w", err)
	}

	for _, proof := range proofs {
		if err := s.validateProof(keysets, proof); err != nil {
			return fmt.Errorf("s.validateProof(keysets, proof): %w", err)
		}
	}

	return nil
}

func (s *Signer) validateProof(keysets map[string]MintKeyset, proof goNutsCashu.Proof) error {
	keyset, exists := keysets[proof.Id]
	if !exists {
		return cashu.ErrKeysetForProofNotFound
	}

	keypair := keyset.Keys[proof.Amount]
	unBlindedBytes, err := hex.DecodeString(proof.C)
	if err != nil {
		return fmt.Errorf("hex.DecodeString(proof.C) %w %w", cashu.ErrInvalidProof, err)
	}
	unBlindedSig, err := secp256k1.ParsePubKey(unBlindedBytes)
	if err != nil {
		return fmt.Errorf("secp256k1.ParsePubKey(unBlindedBytes): %w %w", cashu.ErrInvalidProof, err)
	}
	if !crypto.Verify(proof.Secret, keypair.PrivateKey, unBlindedSig) {
		return fmt.Errorf("crypto.Verify(proof.Secret, keypair.PrivateKey, unBlindedSig): %w", cashu.ErrInvalidProof)
	}

	nut10Secret, err := nut10.DeserializeSecret(proof.Secret)
	if err == nil {
		switch nut10Secret.Kind {
		case nut10.P2PK:
			if err := verifyP2PKLockedProof(proof, nut10Secret); err != nil {
				return fmt.Errorf("verifyP2PKLockedProof(proof, nut10Secret): %w %w", cashu.ErrInvalidProof, err)
			}
		case nut10.HTLC:
			if err := verifyHTLCProof(proof, nut10Secret); err != nil {
				return fmt.Errorf("verifyHTLCProof(proof, nut10Secret): %w %w", cashu.ErrInvalidProof, err)
			}
		}
	}

	return nil
}

func (s *Signer) GetSignerPubkey(signerInfo SignerInfo) ([]byte, error) {
	store, err := s.accounts.GetAccount(signerInfo.AccountID)
	if err != nil {
		return nil, err
	}
	pubkey := store.GetPubkey()
	if pubkey == nil {
		return nil, fmt.Errorf("no public key for account %s", signerInfo.AccountID)
	}
	return pubkey.SerializeCompressed(), nil
}

func (s *Signer) AddKeysToSignerFromAccount(accountID string) error {
	account, err := s.db.GetAccountByID(accountID)
	if err != nil {
		return fmt.Errorf("s.db.GetAccountByID(accountID): %w", err)
	}
	tx, err := s.db.Db.Begin()
	if err != nil {
		return fmt.Errorf("s.db.Db.Begin(): %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	seeds, err := s.db.GetSeedsByAccountID(tx, accountID)
	if err != nil {
		return fmt.Errorf("s.db.GetSeedsByAccountID(tx, accountID): %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("tx.Commit(): %w", err)
	}
	return s.loadAccount(*account, seeds, "")
}

func (s *Signer) findOrGenerateANewSeedphrase() (string, error) {
	envMnemonic := os.Getenv("MNEMONIC")
	defer func() {
		envMnemonic = ""
	}()

	if len(envMnemonic) > 0 {
		if !bip39.IsMnemonicValid(envMnemonic) {
			return "", fmt.Errorf("invalid mnemonic seedphrase")
		}
		if err := StoreSeedPhrase(envMnemonic); err != nil {
			return "", fmt.Errorf("StoreSeedPhrase(mnemonic): %w", err)
		}
		return envMnemonic, nil
	}

	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", fmt.Errorf("bip39.NewEntropy(256): %w", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("bip39.NewMnemonic(entropy): %w", err)
	}
	if err := StoreSeedPhrase(mnemonic); err != nil {
		return "", fmt.Errorf("StoreSeedPhrase(mnemonic): %w", err)
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
	if p2pkTags.Locktime > 0 && time.Now().Local().Unix() > p2pkTags.Locktime {
		if len(p2pkTags.Refund) == 0 {
			return nil
		}
		hash := sha256.Sum256([]byte(proof.Secret))
		if len(p2pkWitness.Signatures) < 1 {
			return nut11.InvalidWitness
		}
		if !nut11.HasValidSignatures(hash[:], p2pkWitness.Signatures, signaturesRequired, p2pkTags.Refund) {
			return nut11.NotEnoughSignaturesErr
		}
		return nil
	}

	pubkey, err := nut11.ParsePublicKey(proofSecret.Data.Data)
	if err != nil {
		return err
	}
	keys := []*btcec.PublicKey{pubkey}
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

	if p2pkTags.Locktime > 0 && time.Now().Local().Unix() > p2pkTags.Locktime {
		if len(p2pkTags.Refund) == 0 {
			return nil
		}
		hash := sha256.Sum256([]byte(proof.Secret))
		if len(htlcWitness.Signatures) < 1 {
			return nut11.InvalidWitness
		}
		if !nut11.HasValidSignatures(hash[:], htlcWitness.Signatures, 1, p2pkTags.Refund) {
			return nut11.NotEnoughSignaturesErr
		}
		return nil
	}

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

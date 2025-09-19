package web

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"nutmix_remote_signer/account_manager"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

type authData struct {
	vals map[string]bool
	sync.Mutex
}

func generateNonceHex() (string, error) {
	// generate random Nonce
	nonce := make([]byte, 32)  // create a slice with length 16 for the nonce
	_, err := rand.Read(nonce) // read random bytes into the nonce slice
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(nonce), nil
}

func (a *authData) CheckNonce(nonce string) bool {
	a.Lock()
	defer a.Unlock()

	val, exists := a.vals[nonce]
	if !exists {
		return false
	}

	return val
}

func (a *authData) MakeNonce() (string, error) {
	a.Lock()
	defer a.Unlock()
	nonce, err := generateNonceHex()
	if err != nil {
		return "", fmt.Errorf("Could not generate nonce. %w", err)
	}

	_, exists := a.vals[nonce]
	if exists {
		return "", fmt.Errorf("nonce already generated")
	}

	a.vals[nonce] = true

	return nonce, nil
}

type ServerData struct {
	auth      authData
	manager   *accountmanager.Manager
	adminNpub *btcec.PublicKey
}

func isNostrKeyValid(nostrKey string) (bool, error) {
	_, key, err := nip19.Decode(nostrKey)
	if err != nil {
		return false, fmt.Errorf("nip19.Decode(key): %w ", err)
	}
	return nostr.IsValid32ByteHex(key.(string)), nil
}

func ParseNip19NpubToPubkey(npub string) (*btcec.PublicKey, error) {
	valid, err := isNostrKeyValid(npub)
	if err != nil {
		return nil, fmt.Errorf("isNostrKeyValid(npub): %w ", err)
	}
	if !valid {
		return nil, fmt.Errorf("Invalid nostr key: %w ", err)
	}
	prefix, value, err := nip19.Decode(npub)
	if err != nil {
		return nil, fmt.Errorf("nip19.Decode(npub): %w ", err)
	}
	if prefix != "npub" {
		return nil, fmt.Errorf("admin npub is not an npub: %w ", err)
	}

	decodedKey, err := hex.DecodeString(value.(string))
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString(npub): %w ", err)
	}

	pubkey, err := schnorr.ParsePubKey(decodedKey)
	if err != nil {
		return nil, fmt.Errorf("schnorr.ParsePubKey(decodedKey): %w ", err)
	}
	return pubkey, nil
}

func NewServerData(mgr *accountmanager.Manager) (*ServerData, error) {
	serverData := ServerData{
		auth:      authData{vals: make(map[string]bool)},
		manager:   mgr,
		adminNpub: nil,
	}

	adminNpub := os.Getenv("ADMIN_NPUB")
	if adminNpub != "" {
		adminPubkey, err := ParseNip19NpubToPubkey(adminNpub)
		if err != nil {
			return &serverData, fmt.Errorf("ParseNip19NpubToPubkey(adminNpub). %w", err)
		}
		if adminPubkey == nil {
			log.Panicf("Admin pubkey should not have been null at this point. because of the error handling before")
		}
		serverData.adminNpub = adminPubkey

	}
	return &serverData, nil
}

func RunHTTPServer(addr string, manager *accountmanager.Manager) error {
	data, err := NewServerData(manager)
	if err != nil {
		return fmt.Errorf("NewServerData(manager). %w", err)
	}
	if data.manager == nil {
		panic("manager should never be null at the after NewServerData")
	}
	router := NewRouter(data)
	return http.ListenAndServe(addr, router)
}

package web

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"

	"nutmix_remote_signer/account_manager"
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
	auth    authData
	manager *accountmanager.Manager
}

func NewServerData(mgr *accountmanager.Manager) *ServerData {
	return &ServerData{
		auth:    authData{vals: make(map[string]bool)},
		manager: mgr,
	}
}

func RunHTTPServer(addr string, manager *accountmanager.Manager ) error {
	data := NewServerData(manager)
	router := NewRouter(data)
	return http.ListenAndServe(addr, router)
}

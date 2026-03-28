package signer

import (
	"fmt"
	"sync"
)

type AccountsStore struct {
	accounts map[string]*KeysetStore
	mu       sync.RWMutex
}

func NewAccountsStore() *AccountsStore {
	return &AccountsStore{accounts: make(map[string]*KeysetStore)}
}

func (a *AccountsStore) AddAccount(id string, store *KeysetStore) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.accounts[id]; ok {
		return fmt.Errorf("account already exists: %s", id)
	}
	a.accounts[id] = store
	return nil
}

func (a *AccountsStore) ReplaceAccount(id string, store *KeysetStore) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.accounts[id]; !ok {
		return fmt.Errorf("account does not exist: %s", id)
	}
	a.accounts[id] = store
	return nil
}

func (a *AccountsStore) SetAccount(id string, store *KeysetStore) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.accounts[id] = store
}

func (a *AccountsStore) GetAccount(id string) (*KeysetStore, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	store, ok := a.accounts[id]
	if !ok {
		return nil, fmt.Errorf("account does not exist: %s", id)
	}
	return store, nil
}

func (a *AccountsStore) GetAllAccounts() map[string]*KeysetStore {
	a.mu.RLock()
	defer a.mu.RUnlock()
	copyMap := make(map[string]*KeysetStore, len(a.accounts))
	for key, value := range a.accounts {
		copyMap[key] = value
	}
	return copyMap
}

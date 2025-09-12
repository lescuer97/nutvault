package signer

import (
	"sync"

	"nutmix_remote_signer/database"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// KeysetStore groups keysets, active keysets and indexes with a mutex
// and provides concurrency-safe accessors.
type KeysetStore struct {
	mu            sync.RWMutex
	keysets       map[string]MintPublicKeyset
	activeKeysets map[string]MintPublicKeyset
	indexes       KeysetGenerationIndexes
	pubkey *secp256k1.PublicKey
}

func NewKeysetStore() KeysetStore {
	return KeysetStore{
		keysets:       make(map[string]MintPublicKeyset),
		activeKeysets: make(map[string]MintPublicKeyset),
		indexes:       make(KeysetGenerationIndexes),
	}
}

func (k *KeysetStore) SetAll(keysets map[string]MintPublicKeyset, active map[string]MintPublicKeyset) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keysets = keysets
	k.activeKeysets = active
}
func (k *KeysetStore) SetPubkey(pubkey *secp256k1.PublicKey) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.pubkey = pubkey
}

func (k *KeysetStore) GetKeysetsList() []MintPublicKeyset {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]MintPublicKeyset, 0, len(k.keysets))
	for _, v := range k.keysets {
		out = append(out, v)
	}
	return out
}

func (k *KeysetStore) GetKeysetsMapCopy() map[string]MintPublicKeyset {
	k.mu.RLock()
	defer k.mu.RUnlock()
	m := make(map[string]MintPublicKeyset, len(k.keysets))
	for kk, vv := range k.keysets {
		m[kk] = vv
	}
	return m
}

func (k *KeysetStore) GetActiveKeysetsCopy() map[string]MintPublicKeyset {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.activeKeysets
}

func (k *KeysetStore) GetIndex(id string) (map[uint64]int, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.indexes == nil {
		return nil, false
	}
	m, ok := k.indexes[id]
	return m, ok
}

func (k *KeysetStore) SetIndexesFromSeeds(seeds []database.Seed) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.indexes == nil {
		k.indexes = make(KeysetGenerationIndexes)
	}
	for _, seed := range seeds {
		if _, exists := k.indexes[seed.Id]; !exists {
			k.indexes[seed.Id] = make(map[uint64]int)
		}
		for index, val := range seed.Amounts {
			k.indexes[seed.Id][val] = index
		}
	}
}

func (k *KeysetStore) GetKeysetById(id string) (MintPublicKeyset, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	v, ok := k.keysets[id]
	return v, ok
}

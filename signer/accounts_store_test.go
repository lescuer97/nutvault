package signer

import "testing"

func TestAccountsStore(t *testing.T) {
	store := NewAccountsStore()
	accountA := NewKeysetStore()
	accountB := NewKeysetStore()

	if err := store.AddAccount("a", accountA); err != nil {
		t.Fatalf("store.AddAccount("+"a"+", accountA): %v", err)
	}
	if _, err := store.GetAccount("missing"); err == nil {
		t.Fatalf("expected missing account lookup to fail")
	}
	if err := store.ReplaceAccount("a", accountB); err != nil {
		t.Fatalf("store.ReplaceAccount("+"a"+", accountB): %v", err)
	}
	got, err := store.GetAccount("a")
	if err != nil {
		t.Fatalf("store.GetAccount("+"a"+"): %v", err)
	}
	if got != accountB {
		t.Fatalf("GetAccount returned wrong store")
	}
}

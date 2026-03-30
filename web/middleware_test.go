package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func TestAuthMiddlewareRedirectsUnauthenticated(t *testing.T) {
	secret := []byte("secret")
	handler := AuthMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusTemporaryRedirect {
		t.Fatalf("resp.Code = %d, want %d", resp.Code, http.StatusTemporaryRedirect)
	}
}

func TestAuthMiddlewareSetsSubjectPubkeyInContext(t *testing.T) {
	secret := []byte("secret")
	priv, _ := btcec.PrivKeyFromBytes([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	token, err := makeJWTToken(secret, priv.PubKey())
	if err != nil {
		t.Fatalf("makeJWTToken(...): %v", err)
	}

	called := false
	handler := AuthMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		pubkey, err := GetAudience(r)
		if err != nil {
			t.Fatalf("GetAudience(r): %v", err)
		}
		if !pubkey.IsEqual(priv.PubKey()) {
			t.Fatalf("unexpected pubkey from context")
		}
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: AdminAuthKey, Value: token})
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if !called {
		t.Fatalf("expected wrapped handler to be called")
	}
	if resp.Code != http.StatusOK {
		t.Fatalf("resp.Code = %d, want %d", resp.Code, http.StatusOK)
	}
}

func TestOwnershipCheck(t *testing.T) {
	serverData, _, account, _ := setupWebTestServerData(t)
	otherPriv, _ := btcec.PrivKeyFromBytes([]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9})
	req := withAccountRequestContext(httptest.NewRequest(http.MethodGet, "/signer/"+account.Id, nil), account.Id, otherPriv.PubKey())
	_, err := VerifyIdInRequestIsAvailable(serverData, req)
	if err == nil {
		t.Fatalf("expected ownership verification to fail")
	}
}

func withAudienceContext(req *http.Request, pubkey *btcec.PublicKey) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), audienceKey, hexPub(pubkey)))
}

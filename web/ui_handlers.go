package web

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"nutmix_remote_signer/web/templates"
)

// DashboardHandler renders the accounts dashboard (uses package-level DB if available)
func DashboardHandler(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Attempt to load accounts from DB if present
		var _ []map[string]string
		if serverData.manager != nil {
			// accounts, err := serverData.manager.GetAccountsWithSeeds()
			// if err == nil {
			// 	for _, a := range accounts {
			// 		card := map[string]string{
			// 			"id":     a.Account.Id,
			// 			"name":   a.Account.Id,
			// 			"pubkey": fmt.Sprintf("%x", a.Account.Npub),
			// 		}
			// 		cards = append(cards, card)
			// 	}
			// }
		}

		templates.Dashboard().Render(r.Context(), w)
	}
}

// CreateKeyHandler is a lightweight mock create endpoint for HTMX.
// It returns a single card fragment that HTMX can insert. The created key is NOT persisted.
func CreateKeyHandler(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If a manager is available on serverData, call it to create and persist account
		if serverData != nil && serverData.manager != nil {
			// In a real flow, we would extract the logged-in user's pubkey or client fingerprint.
			// For now assume the logged-in user's npub is available via a header "X-Client-Pubkey-HEX"
			hexPub := r.Header.Get("X-Client-Pubkey-HEX")
			if hexPub == "" {
				// Fallback to mock behavior if header not present
				now := time.Now()
				id := fmt.Sprintf("mock-%d", now.UnixNano())
				templates.KeyCard(id, "New Key", now.Unix(), "deadbeefcafebabefakepubkey").Render(r.Context(), w)
				return
			}

			pubBytes, err := hex.DecodeString(hexPub)
			if err != nil {
				http.Error(w, "invalid pubkey", http.StatusBadRequest)
				return
			}
			pubkey, err := btcec.ParsePubKey(pubBytes)
			if err != nil {
				http.Error(w, "invalid pubkey bytes", http.StatusBadRequest)
				return
			}

			acct, err := serverData.manager.CreateAccount(r.Context(), pubkey)
			if err != nil {
				http.Error(w, "failed to create account", http.StatusInternalServerError)
				return
			}

			templates.KeyCard(acct.Id, acct.Id, acct.CreatedAt, fmt.Sprintf("%x", acct.Npub)).Render(r.Context(), w)
			return
		}

		// No manager: fallback mock
		now := time.Now()
		id := fmt.Sprintf("mock-%d", now.UnixNano())
		templates.KeyCard(id, "New Key", now.Unix(), "deadbeefcafebabefakepubkey").Render(r.Context(), w)
	}
}

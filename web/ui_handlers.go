package web

import (
	"fmt"
	"net/http"
	"time"

	"nutmix_remote_signer/web/templates"
)

// DashboardHandler renders the accounts dashboard (uses package-level DB if available)
func DashboardHandler(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pubkey, err := GetAudience(r)
		if err != nil {
			http.Error(w, "Invalid login", http.StatusUnauthorized)
			return
		}
		// Attempt to load accounts from DB if present
		var cards []map[string]string
		if serverData.manager != nil {
			accounts, err := serverData.manager.GetAccountsFromNpub(pubkey)
			if err == nil {
				for _, a := range accounts {
					card := map[string]string{
						"id":     a.Id,
						"name":   a.Id,
						"pubkey": fmt.Sprintf("%x", a.Npub),
					}
					cards = append(cards, card)
				}
			}
		}

		templates.Dashboard().Render(r.Context(), w)
	}
}

// CreateKeyHandler is a lightweight mock create endpoint for HTMX.
// It returns a single card fragment that HTMX can insert. The created key is NOT persisted.
func CreateKeyHandler(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pubkey, err := GetAudience(r)
		if err != nil {
			http.Error(w, "Invalid login", http.StatusUnauthorized)
			return
		}
		// If a manager is available on serverData, call it to create and persist account
		if serverData != nil && serverData.manager != nil {
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

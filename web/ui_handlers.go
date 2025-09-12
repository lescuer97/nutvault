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
		// Attempt to load accounts from DB if present
		var cards []map[string]string
		if DB != nil {
			accounts, err := DB.GetAccountsWithSeeds()
			if err == nil {
				for _, a := range accounts {
					card := map[string]string{
						"id":     a.Account.Id,
						"name":   a.Account.Id,
						"pubkey": fmt.Sprintf("%x", a.Account.Npub),
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
		// Create a mock key card (non-persistent)
		now := time.Now()
		id := fmt.Sprintf("mock-%d", now.UnixNano())
		// Use same args as templ.Card expects: id, name, createdAt, pubkey
		templates.KeyCard(id, "New Key", now.Unix(), "deadbeefcafebabefakepubkey").Render(r.Context(), w)
	}
}

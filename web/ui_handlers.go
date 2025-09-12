package web

import (
	"net/http"

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
		// Attempt to load accounts from DB if present and render Dashboard
		if serverData.manager != nil {
			accounts, err := serverData.manager.GetAccountsFromNpub(pubkey)
			if err == nil {
				templates.Dashboard(accounts).Render(r.Context(), w)
				return
			}
		}

		templates.Dashboard(nil).Render(r.Context(), w)
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
			acct, err := serverData.manager.CreateAccount(r.Context(), pubkey)
			if err != nil {
				http.Error(w, "failed to create account", http.StatusInternalServerError)
				return
			}

			templates.KeyCard(*acct).Render(r.Context(), w)
			return
	}
}

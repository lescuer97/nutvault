package web

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"

	"nutmix_remote_signer/web/templates"

	"github.com/go-chi/chi/v5"
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
			slog.Error("serverData.manager.CreateAccount(r.Context(), pubkey)", slog.Any("error", err))
			http.Error(w, "failed to create account", http.StatusInternalServerError)
			return
		}

		templates.KeyCard(*acct).Render(r.Context(), w)
		return
	}
}

// helper: render CertPre templ component and write to ResponseWriter
func writeCertPre(w http.ResponseWriter, r *http.Request, id, content string) error {
	var buf bytes.Buffer
	if err := templates.CertPre(id, content).Render(r.Context(), &buf); err != nil {
		slog.Error("templ render failed", slog.Any("error", err), slog.String("id", id))
		http.Error(w, "render failed", http.StatusInternalServerError)
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(buf.Bytes()); err != nil {
		slog.Error("write response failed", slog.Any("error", err), slog.String("id", id))
		return err
	}
	return nil
}

// SignerDashboard renders the signer-specific dashboard page
func SignerDashboard(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		account, err := serverData.manager.GetAccountById(id)
		if err != nil {
			if err == sql.ErrNoRows {
				http.NotFound(w, r)
				return
			}
			slog.Error("GetAccountById", slog.Any("error", err))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		templates.SignerDashboard(*account).Render(r.Context(), w)
	}
}

// CertHandler serves certificate content for HTMX requests. {which} is ca, cert, or key
// Access control: verifies that the authenticated audience (token) matches the account's npub
// Audit logging: logs successful and failed reveal attempts without exposing secret contents
func CertHandler(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		which := chi.URLParam(r, "which")
		if serverData == nil || serverData.manager == nil {
			http.Error(w, "server not configured", http.StatusInternalServerError)
			slog.Warn("cert_reveal_failed", slog.String("reason", "server_not_configured"), slog.String("account_id", id), slog.String("which", which), slog.String("remote", r.RemoteAddr))
			return
		}

		// Fetch account and ensure it exists
		account, err := serverData.manager.GetAccountById(id)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "account not found", http.StatusNotFound)
				slog.Warn("cert_reveal_failed", slog.String("reason", "account_not_found"), slog.String("account_id", id), slog.String("which", which), slog.String("remote", r.RemoteAddr))
				return
			}
			http.Error(w, "failed to load account", http.StatusInternalServerError)
			slog.Error("cert_reveal_failed", slog.Any("error", err), slog.String("account_id", id), slog.String("which", which), slog.String("remote", r.RemoteAddr))
			return
		}

		// Get the token audience (public key) and ensure it matches account.Npub
		audPub, err := GetAudience(r)
		if err != nil {
			http.Error(w, "invalid audience", http.StatusUnauthorized)
			slog.Warn("cert_reveal_failed", slog.String("reason", "invalid_audience"), slog.String("account_id", id), slog.String("which", which), slog.String("remote", r.RemoteAddr))
			return
		}
		audHex := hex.EncodeToString(audPub.SerializeCompressed())
		if !bytes.Equal(audPub.SerializeCompressed(), account.Npub) {
			http.Error(w, "forbidden: token does not have access to this account", http.StatusForbidden)
			slog.Warn("cert_reveal_forbidden", slog.String("account_id", id), slog.String("requester_npub", audHex), slog.String("which", which), slog.String("remote", r.RemoteAddr))
			return
		}

		// At this point the requester is authorized to read the requested artifact
		switch which {
		case "ca":
			// CA cert via accessor
			ca := serverData.manager.GetCACertPEM()
			if len(ca) == 0 {
				http.Error(w, "CA certificate not configured", http.StatusNotFound)
				slog.Warn("cert_reveal_failed", slog.String("reason", "ca_not_configured"), slog.String("account_id", id), slog.String("requester_npub", audHex), slog.String("which", which), slog.String("remote", r.RemoteAddr))
				return
			}
			if err := writeCertPre(w, r, "ca-"+id, string(ca)); err == nil {
				slog.Info("cert_reveal_success", slog.String("account_id", id), slog.String("requester_npub", audHex), slog.String("which", which), slog.Int("bytes", len(ca)), slog.String("remote", r.RemoteAddr))
			}
			return
		case "cert":
			data, err := serverData.manager.GetCertificate(id)
			if err != nil {
				http.Error(w, "certificate not found", http.StatusNotFound)
				slog.Warn("cert_reveal_failed", slog.String("reason", "cert_missing"), slog.String("account_id", id), slog.String("requester_npub", audHex), slog.String("which", which), slog.String("remote", r.RemoteAddr))
				return
			}
			if err := writeCertPre(w, r, "cert-"+id, string(data)); err == nil {
				slog.Info("cert_reveal_success", slog.String("account_id", id), slog.String("requester_npub", audHex), slog.String("which", which), slog.Int("bytes", len(data)), slog.String("remote", r.RemoteAddr))
			}
			return
		case "key":
			// Key path: try name-key.pem
			dir := serverData.manager.TlsConfigDir()
			if dir == "" {
				http.Error(w, "tls dir not configured", http.StatusInternalServerError)
				slog.Error("cert_reveal_failed", slog.String("reason", "tls_dir_missing"), slog.String("account_id", id), slog.String("requester_npub", audHex), slog.String("which", which), slog.String("remote", r.RemoteAddr))
				return
			}
			p := dir + "/" + id + "-key.pem"
			data, err := os.ReadFile(p)
			if err != nil {
				http.Error(w, "key not found", http.StatusNotFound)
				slog.Warn("cert_reveal_failed", slog.String("reason", "key_missing"), slog.String("account_id", id), slog.String("requester_npub", audHex), slog.String("which", which), slog.String("path", p), slog.String("remote", r.RemoteAddr))
				return
			}
			if err := writeCertPre(w, r, "key-"+id, string(data)); err == nil {
				slog.Info("cert_reveal_success", slog.String("account_id", id), slog.String("requester_npub", audHex), slog.String("which", which), slog.Int("bytes", len(data)), slog.String("remote", r.RemoteAddr))
			}
			return
		default:
			http.Error(w, "invalid cert type", http.StatusBadRequest)
			slog.Warn("cert_reveal_failed", slog.String("reason", "invalid_type"), slog.String("account_id", id), slog.String("requester_npub", audHex), slog.String("which", which), slog.String("remote", r.RemoteAddr))
			return
		}
	}
}

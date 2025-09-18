package web

import (
	"bytes"
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"

	"nutmix_remote_signer/web/templates"
)

var (
	validate = validator.New()
	// allowed which values
	allowedWhich = map[string]string{"ca": "CA Certificate", "cert": "TLS Certificate", "key": "TLS Key"}
)

// helper: render a closed row with blind text and closed-eye button
func writeClosedRow(w http.ResponseWriter, r *http.Request, accountId, which, label string) error {
	var buf bytes.Buffer
	if err := templates.CertRow(accountId, which, label, false, "").Render(r.Context(), &buf); err != nil {
		slog.Error("templ render failed", slog.Any("error", err), slog.String("which", which))
		http.Error(w, "render failed", http.StatusInternalServerError)
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err := w.Write(buf.Bytes())
	return err
}

// helper: render an open row with cert content and open-eye button
func writeOpenRow(w http.ResponseWriter, r *http.Request, accountId, which, label, content string) error {
	var buf bytes.Buffer
	if err := templates.CertRow(accountId, which, label, true, content).Render(r.Context(), &buf); err != nil {
		slog.Error("templ render failed", slog.Any("error", err), slog.String("which", which))
		http.Error(w, "render failed", http.StatusInternalServerError)
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err := w.Write(buf.Bytes())
	return err
}

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

// SignerDashboard renders the signer-specific dashboard page
func SignerDashboard(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if err := sanitizeId(id); err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}
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

// API endpoint to update account name
// Simplified: only accept form submissions and require the "name" field
func UpdateAccountNameHandler(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		account, err := VerifyIdInRequestIsAvailable(serverData, r)
		if err != nil {
			slog.Error("VerifyIdInRequestIsAvailable(serverData, r)", slog.Any("error", err))
			http.Error(w, "you don't have access to the signer", http.StatusInternalServerError)
			return
		}
		if account == nil {
			panic("account should never be nil at this point")
		}
		// Ensure request is a form submission
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/x-www-form-urlencoded") && !strings.HasPrefix(ct, "multipart/form-data") {
			http.Error(w, "expected form submission", http.StatusBadRequest)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		newName := strings.TrimSpace(r.FormValue("name"))
		if newName == "" {
			http.Error(w, "empty name", http.StatusBadRequest)
			return
		}

		account.Name = newName

		if err := serverData.manager.UpdateAccountName(r.Context(), account.Id, account.Name); err != nil {
			slog.Error("UpdateAccountName failed", slog.Any("error", err))
			http.Error(w, "failed to update", http.StatusInternalServerError)
			return
		}

		var buf bytes.Buffer
		if err := templates.KeyCardNoButton(*account).Render(r.Context(), &buf); err != nil {
			slog.Error("render card fragment failed", slog.Any("error", err))
			http.Error(w, "render failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}
}

// CertHandler serves certificate content for HTMX requests. {which} is ca, cert, or key
func CertHandler(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		account, err := VerifyIdInRequestIsAvailable(serverData, r)
		if err != nil {
			slog.Error("VerifyIdInRequestIsAvailable(serverData, r)", slog.Any("error", err))
			http.Error(w, "you don't have access to the signer", http.StatusInternalServerError)
			return
		}

		if account == nil {
			panic("account should never be nil at this point")
		}

		which := chi.URLParam(r, "which")

		label, err := sanitizeWhich(which)
		if err != nil {
			http.Error(w, "invalid type", http.StatusBadRequest)
			return
		}

		audPub, err := GetAudience(r)
		if err != nil {
			http.Error(w, "invalid audience", http.StatusUnauthorized)
			return
		}
		if !bytes.Equal(audPub.SerializeCompressed(), account.Npub) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		switch which {
		case "ca":
			ca := serverData.manager.GetCACertPEM()
			if len(ca) == 0 {
				http.Error(w, "CA certificate not configured", http.StatusNotFound)
				return
			}
			_ = writeOpenRow(w, r, account.Id, which, label, string(ca))
			return
		case "cert":
			data, err := serverData.manager.GetCertificate(account.Id)
			if err != nil {
				http.Error(w, "certificate not found", http.StatusNotFound)
				return
			}
			_ = writeOpenRow(w, r, account.Id, which, label, string(data))
			return
		case "key":
			dir := serverData.manager.TlsConfigDir()
			if dir == "" {
				http.Error(w, "tls dir not configured", http.StatusInternalServerError)
				return
			}
			keyFileName := account.Id + "-key.pem"
			keyPath, err := safeJoinFile(dir, keyFileName)
			if err != nil {
				http.Error(w, "invalid key path", http.StatusBadRequest)
				return
			}
			data, err := os.ReadFile(keyPath)
			if err != nil {
				http.Error(w, "key not found", http.StatusNotFound)
				return
			}
			_ = writeOpenRow(w, r, account.Id, which, label, string(data))
			return
		default:
			http.Error(w, "invalid cert type", http.StatusBadRequest)
			return
		}
	}
}

// CertDownloadHandler serves the certificate/key/ca as an attachment for download
func CertDownloadHandler(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		which := chi.URLParam(r, "which")

		account, err := VerifyIdInRequestIsAvailable(serverData, r)
		if err != nil {
			slog.Error("VerifyIdInRequestIsAvailable(serverData, r)", slog.Any("error", err))
			http.Error(w, "you don't have access to the signer", http.StatusInternalServerError)
			return
		}
		if account == nil {
			panic("account should never be nil at this point")
		}

		if _, err := sanitizeWhich(which); err != nil {
			http.Error(w, "invalid type", http.StatusBadRequest)
			return
		}

		var data []byte
		var fname string
		switch which {
		case "ca":
			data = serverData.manager.GetCACertPEM()
			if len(data) == 0 {
				http.Error(w, "CA certificate not configured", http.StatusNotFound)
				return
			}
			fname = sanitizeFileName(account.Name) + "-ca.pem"
		case "cert":
			d, err := serverData.manager.GetCertificate(account.Id)
			if err != nil {
				http.Error(w, "certificate not found", http.StatusNotFound)
				return
			}
			data = d
			fname = sanitizeFileName(account.Name) + "-cert.pem"
		case "key":
			dir := serverData.manager.TlsConfigDir()
			if dir == "" {
				http.Error(w, "tls dir not configured", http.StatusInternalServerError)
				return
			}
			keyFileName := account.Id + "-key.pem"
			keyPath, err := safeJoinFile(dir, keyFileName)
			if err != nil {
				http.Error(w, "invalid key path", http.StatusBadRequest)
				return
			}
			d, err := os.ReadFile(keyPath)
			if err != nil {
				http.Error(w, "key not found", http.StatusNotFound)
				return
			}
			data = d
			fname = sanitizeFileName(account.Name) + "-key.pem"
		default:
			http.Error(w, "invalid cert type", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+fname+"\"")
		http.ServeContent(w, r, fname, time.Now(), bytes.NewReader(data))
	}
}

// HideCertHandler returns the closed row (blind text + closed-eye button)
func HideCertHandler(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		account, err := VerifyIdInRequestIsAvailable(serverData, r)
		if err != nil {
			slog.Error("VerifyIdInRequestIsAvailable(serverData, r)", slog.Any("error", err))
			http.Error(w, "you don't have access to the signer", http.StatusInternalServerError)
			return
		}
		if account == nil {
			panic("account should never be nil at this point")
		}
		which := chi.URLParam(r, "which")
		label, err := sanitizeWhich(which)
		if err != nil {
			http.Error(w, "invalid type", http.StatusBadRequest)
			return
		}

		_ = writeClosedRow(w, r, account.Id, which, label)
	}
}

// KeysetsListHandler returns the keysets fragment with ownership verification
func KeysetsListHandler(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if serverData == nil {
			panic("Server data should not be nil ever at this point")
		}
		if serverData.manager == nil {
			panic("Manager should never be null at this point")
		}

		account, err := VerifyIdInRequestIsAvailable(serverData, r)
		if err != nil {
			slog.Error("VerifyIdInRequestIsAvailable(serverData, r)", slog.Any("error", err))
			http.Error(w, "you don't have access to the signer", http.StatusInternalServerError)
			return
		}
		if account == nil {
			panic("account should never be nil at this point")
		}
		// Fetch seeds (keysets)
		seeds, err := serverData.manager.GetKeysetsForAccount(r.Context(), account.Id)
		if err != nil {
			slog.Error("GetKeysetsForAccount", slog.Any("error", err))
			http.Error(w, "failed to load keysets", http.StatusInternalServerError)
			return
		}

		var buf bytes.Buffer
		if err := templates.KeysetsList(seeds).Render(r.Context(), &buf); err != nil {
			slog.Error("render keysets list failed", slog.Any("error", err))
			http.Error(w, "render failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}
}

// API endpoint to update account name
// Simplified: only accept form submissions and require the "name" field
func ChangeSignerActivation(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		account, err := VerifyIdInRequestIsAvailable(serverData, r)
		if err != nil {
			slog.Error("VerifyIdInRequestIsAvailable(serverData, r)", slog.Any("error", err))
			http.Error(w, "you don't have access to the signer", http.StatusInternalServerError)
			return
		}
		if account == nil {
			panic("account should never be nil at this point")
		}

		// Ensure request is a form submission
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/x-www-form-urlencoded") && !strings.HasPrefix(ct, "multipart/form-data") {
			http.Error(w, "expected form submission", http.StatusBadRequest)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		newName := strings.TrimSpace(r.FormValue("name"))
		if newName == "" {
			http.Error(w, "empty name", http.StatusBadRequest)
			return
		}

		if err := serverData.manager.UpdateAccountName(r.Context(), account.Id, newName); err != nil {
			slog.Error("UpdateAccountName failed", slog.Any("error", err))
			http.Error(w, "failed to update", http.StatusInternalServerError)
			return
		}

		// Fetch updated account and render the whole card fragment so HTMX can swap the card
		updatedAccount, err := serverData.manager.GetAccountById(account.Id)
		if err != nil {
			slog.Error("GetAccountById after update failed", slog.Any("error", err))
			http.Error(w, "failed to load account", http.StatusInternalServerError)
			return
		}

		var buf bytes.Buffer
		if err := templates.KeyCardNoButton(*updatedAccount).Render(r.Context(), &buf); err != nil {
			slog.Error("render card fragment failed", slog.Any("error", err))
			http.Error(w, "render failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}
}

// ToggleAccountActiveHandler toggles the active status of an account and its seeds
func ToggleAccountActiveHandler(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		account, err := VerifyIdInRequestIsAvailable(serverData, r)
		if err != nil {
			slog.Error("VerifyIdInRequestIsAvailable(serverData, r)", slog.Any("error", err))
			http.Error(w, "you don't have access to the signer", http.StatusInternalServerError)
			return
		}
		if account == nil {
			panic("account should never be nil at this point")
		}
		account.Active = !account.Active

		// Toggle the account active status
		if err := serverData.manager.SetAccountActive(r.Context(), account.Id, account.Active); err != nil {
			slog.Error("SetAccountActive", slog.Any("error", err))
			http.Error(w, "failed to update", http.StatusInternalServerError)
			return
		}

		// Render just the button fragment for HTMX swap
		templates.SignerToggleButton(account.Id, account.Active).Render(r.Context(), w)
	}
}

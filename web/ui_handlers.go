package web

import (
	"bytes"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"

	"nutmix_remote_signer/web/templates"
)

var (
	validate = validator.New()
	// allowed which values
	allowedWhich = map[string]string{"ca": "CA Certificate", "cert": "TLS Certificate", "key": "TLS Key"}
)

func sanitizeId(id string) error {
	if id == "" {
		return errors.New("empty id")
	}
	// validate hex length 64
	if err := validate.Var(id, "required,len=64,hexadecimal"); err != nil {
		return err
	}
	return nil
}

func sanitizeWhich(which string) (string, error) {
	// use validator oneof for allowed values
	if err := validate.Var(which, "required,oneof=ca cert key"); err != nil {
		return "", err
	}
	return allowedWhich[which], nil
}

// ensure the resolved file path stays within baseDir to prevent directory traversal
func safeJoinFile(baseDir, fileName string) (string, error) {
	if strings.Contains(fileName, "..") || strings.ContainsAny(fileName, "/\\") {
		return "", errors.New("invalid filename")
	}
	joined := filepath.Join(baseDir, fileName)
	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}
	// ensure trailing separator on base for prefix check
	baseWithSep := absBase
	if !strings.HasSuffix(baseWithSep, string(os.PathSeparator)) {
		baseWithSep = baseWithSep + string(os.PathSeparator)
	}
	if !strings.HasPrefix(absJoined, baseWithSep) {
		return "", errors.New("path escapes base directory")
	}
	return absJoined, nil
}

// sanitizeFileName makes a safe short filename from an account name
func sanitizeFileName(name string) string {
	if name == "" {
		return "account"
	}
	// replace spaces with underscores
	name = strings.ReplaceAll(name, " ", "_")
	// map to allowed chars: letters, digits, '-', '_', '.'
	mapped := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, name)
	// trim length
	if len(mapped) > 200 {
		mapped = mapped[:200]
	}
	return mapped
}

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

// SignerDashboard renders the signer-specific dashboard page
func SignerDashboard(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		// sanitize id early
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

// CertHandler serves certificate content for HTMX requests. {which} is ca, cert, or key
// Access control: verifies that the authenticated audience (token) matches the account's npub
// Simplified swapping: returns a full row fragment (open or closed) swapped with outerHTML on the row container
func CertHandler(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		which := chi.URLParam(r, "which")

		// sanitize inputs using go-playground/validator
		if err := sanitizeId(id); err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}
		label, err := sanitizeWhich(which)
		if err != nil {
			http.Error(w, "invalid type", http.StatusBadRequest)
			return
		}

		if serverData == nil || serverData.manager == nil {
			http.Error(w, "server not configured", http.StatusInternalServerError)
			return
		}

		// Fetch account and ensure it exists (GetAccountById uses parameterized queries)
		account, err := serverData.manager.GetAccountById(id)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "account not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to load account", http.StatusInternalServerError)
			return
		}

		// Authorization
		audPub, err := GetAudience(r)
		if err != nil {
			http.Error(w, "invalid audience", http.StatusUnauthorized)
			return
		}
		if !bytes.Equal(audPub.SerializeCompressed(), account.Npub) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		// Load content and render open row
		switch which {
		case "ca":
			ca := serverData.manager.GetCACertPEM()
			if len(ca) == 0 {
				http.Error(w, "CA certificate not configured", http.StatusNotFound)
				return
			}
			_ = writeOpenRow(w, r, id, which, label, string(ca))
			return
		case "cert":
			data, err := serverData.manager.GetCertificate(id)
			if err != nil {
				http.Error(w, "certificate not found", http.StatusNotFound)
				return
			}
			_ = writeOpenRow(w, r, id, which, label, string(data))
			return
		case "key":
			dir := serverData.manager.TlsConfigDir()
			if dir == "" {
				http.Error(w, "tls dir not configured", http.StatusInternalServerError)
				return
			}
			// ensure safe path
			keyFileName := id + "-key.pem"
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
			_ = writeOpenRow(w, r, id, which, label, string(data))
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
		id := chi.URLParam(r, "id")
		which := chi.URLParam(r, "which")

		// sanitize inputs
		if err := sanitizeId(id); err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}
		if _, err := sanitizeWhich(which); err != nil {
			http.Error(w, "invalid type", http.StatusBadRequest)
			return
		}

		if serverData == nil || serverData.manager == nil {
			http.Error(w, "server not configured", http.StatusInternalServerError)
			return
		}

		// Fetch account and ensure it exists
		account, err := serverData.manager.GetAccountById(id)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "account not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to load account", http.StatusInternalServerError)
			return
		}

		// Authorization
		audPub, err := GetAudience(r)
		if err != nil {
			http.Error(w, "invalid audience", http.StatusUnauthorized)
			return
		}
		if !bytes.Equal(audPub.SerializeCompressed(), account.Npub) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		// Load content and serve as attachment
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
			d, err := serverData.manager.GetCertificate(id)
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
			keyFileName := id + "-key.pem"
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

		// Serve file as attachment
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+fname+"\"")
		http.ServeContent(w, r, fname, time.Now(), bytes.NewReader(data))
	}
}

// HideCertHandler returns the closed row (blind text + closed-eye button)
func HideCertHandler(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		which := chi.URLParam(r, "which")

		// sanitize inputs
		if err := sanitizeId(id); err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}
		label, err := sanitizeWhich(which)
		if err != nil {
			http.Error(w, "invalid type", http.StatusBadRequest)
			return
		}

		if serverData == nil || serverData.manager == nil {
			http.Error(w, "server not configured", http.StatusInternalServerError)
			return
		}

		// Authorization: ensure token audience matches account.npub
		account, err := serverData.manager.GetAccountById(id)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "account not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to load account", http.StatusInternalServerError)
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

		_ = writeClosedRow(w, r, id, which, label)
	}
}

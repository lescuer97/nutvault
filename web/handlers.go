package web

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"nutmix_remote_signer/web/templates"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nbd-wtf/go-nostr"
)

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	templates.Hello("World").Render(r.Context(), w)
}

func CreateAccountHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Parse request, construct proto, call gRPC client
	w.WriteHeader(http.StatusNotImplemented)
}

func LoginGetHandler(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		nonce, err := serverData.auth.MakeNonce()
		if err != nil {
			http.Error(w, "Something happened", http.StatusInternalServerError)
		}
		templates.Login(nonce).Render(r.Context(), w)
	}
}

func LoginPostHandler(serverData *ServerData, secret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var nostrEvent nostr.Event
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		defer r.Body.Close()

		err = json.Unmarshal(body, &nostrEvent)
		if err != nil {
			slog.Debug(
				"Incorrect body",
				slog.String("error", err.Error()),
			)
			http.Error(w, "body needs to be a nostr event", http.StatusBadRequest)
			return
		}

		exists := serverData.auth.CheckNonce(nostrEvent.Content)

		if !exists {
			http.Error(w, "Incorrect nonce use", http.StatusBadRequest)
			return

		}

		// check valid signature
		validSig, err := nostrEvent.CheckSignature()
		if err != nil {
			slog.Info("nostrEvent.CheckSignature()", slog.String("erro", err.Error()))
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}

		if !validSig {
			slog.Warn("Invalid Signature")
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}

		token, err := makeJWTToken(secret)

		if err != nil {
			slog.Warn("Could not makeJWTToken", slog.String("error", err.Error()))
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}
		// Create a new cookie
		cookie := &http.Cookie{
			Name:     AdminAuthKey,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Expires:  time.Now().Add(24 * time.Hour),
		}
		http.SetCookie(w, cookie)
	}
}

func GetAccountHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Parse request, construct proto, call gRPC client
	w.WriteHeader(http.StatusNotImplemented)
}

func makeJWTToken(secret []byte) (string, error) {

	token := jwt.New(jwt.SigningMethodHS256)
	string, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("token.SignedString(secret) %v", err)

	}
	return string, nil
}

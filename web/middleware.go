package web

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/golang-jwt/jwt/v5"
)

const AdminAuthKey = "admin-cookie"

type contextKey string

const audienceKey contextKey = "audience"

func AuthMiddleware(secret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			isLoginPath := r.URL.Path == "/login"

			cookie, err := r.Cookie(AdminAuthKey)
			if err != nil {
				// No cookie
				if isLoginPath {
					next.ServeHTTP(w, r)
					return
				}
				w.Header().Set("HX-Location", "/login")
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			// Verify token
			token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return secret, nil
			})

			if err != nil {
				slog.Debug("jwt.Parse error", slog.String("error", err.Error()))
			}

			// Clear invalid cookie
			if err != nil || !token.Valid {
				http.SetCookie(w, &http.Cookie{
					Name:     AdminAuthKey,
					Value:    "",
					MaxAge:   -1,
					Path:     "/",
					HttpOnly: true,
				})

				if isLoginPath && token != nil && !token.Valid {
					next.ServeHTTP(w, r)
					return
				}

				if !isLoginPath {
					w.Header().Set("HX-Redirect", "/login")
					return
				}
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			// Valid token
			if isLoginPath {
				w.Header().Set("HX-Redirect", "/")
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
				return
			}

			// Extract audience claim
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, "invalid claims", http.StatusUnauthorized)
				return
			}

			aud, ok := claims["sub"].(string)
			if !ok {
				http.Error(w, "audience claim missing or not string", http.StatusUnauthorized)
				return
			}

			// Store in context
			ctx := context.WithValue(r.Context(), audienceKey, aud)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Helper to fetch the audience in handlers
func GetAudience(r *http.Request) (*btcec.PublicKey, error) {
	val := r.Context().Value(audienceKey)
	aud, ok := val.(string)

	if !ok {
		return nil, fmt.Errorf("could nto get the public key from login")
	}

	pubBytes, err := hex.DecodeString(aud)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString(aud). %w", err)
	}
	pubkey, err := btcec.ParsePubKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("btcec.ParsePubKey(pubBytes). %w", err)
	}

	return pubkey, nil
}

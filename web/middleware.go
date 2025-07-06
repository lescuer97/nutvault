package web

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

const AdminAuthKey = "admin-cookie"

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

			next.ServeHTTP(w, r)
		})
	}
}

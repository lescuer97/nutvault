package web

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"nutmix_remote_signer/web/templates"

	"github.com/go-playground/form/v4"
)

var (
	decoder = form.NewDecoder()
)

func AdminDashboardHandler(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if serverData == nil {
			panic("server data should have never been nil in post add npub handler")
		}
		authNpubs, err := serverData.manager.GetAllAuthNpubs()
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
			} else {
				http.NotFound(w, r)
				return
			}
		}

		templates.AdminDashboard(authNpubs).Render(r.Context(), w)
	}
}
func AddNpubDialogHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		templates.CreateUserDialog().Render(r.Context(), w)
	}
}

type AddNpubForm struct {
	Npub string `form:"npub" validate:"required"`
	Age  int    `form:"age" validate:"required,min=0"`
}

func PostAddNpubHandler(serverData *ServerData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if serverData == nil {
			panic("server data should have never been nil in post add npub handler")
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}

		// Decode into struct
		var formData AddNpubForm
		if err := decoder.Decode(&formData, r.Form); err != nil {
			http.Error(w, "Failed to decode form", http.StatusBadRequest)
			return
		}

		// Validate the struct
		if err := validate.Struct(formData); err != nil {
			http.Error(w, fmt.Sprintf("Validation error: %v", err), http.StatusBadRequest)
			return
		}

		// serverData.manager.

		templates.CreateUserDialog().Render(r.Context(), w)
	}
}

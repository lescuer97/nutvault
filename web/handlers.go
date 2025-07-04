package web

import (
	"net/http"

	"nutmix_remote_signer/web/templates"
)

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	templates.Hello("World").Render(r.Context(), w)
}

func CreateAccountHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Parse request, construct proto, call gRPC client
	w.WriteHeader(http.StatusNotImplemented)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	templates.Login().Render(r.Context(), w)
}

func LoginPostHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement login logic here
	w.Header().Add("HX-Redirect", "/")
	w.WriteHeader(http.StatusSeeOther)

}

func GetAccountHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Parse request, construct proto, call gRPC client
	w.WriteHeader(http.StatusNotImplemented)
}

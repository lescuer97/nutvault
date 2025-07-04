package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func NewRouter() http.Handler {
	router := chi.NewRouter()


	router.Get("/login", LoginHandler)
	router.Get("/", IndexHandler)

	return router
}

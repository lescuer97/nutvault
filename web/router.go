package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func NewRouter() http.Handler {
	router := chi.NewRouter()

	fs := http.FileServer(http.Dir("./templates"))
	router.Handle("/static/*", http.StripPrefix("/static/", fs))

	router.Get("/login", LoginHandler)
	router.Post("/login", LoginPostHandler)
	router.Get("/", IndexHandler)

	return router
}

package web

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

//go:embed static/*
var static embed.FS

func NewRouter(serverData *ServerData) http.Handler {
	if serverData == nil {
		log.Panic("Server data structure is nil")
	}

	router := chi.NewRouter()

	// Configure the default logger format
	middleware.DefaultLogger = middleware.RequestLogger(
		&middleware.DefaultLogFormatter{
			Logger:  log.New(os.Stdout, "", log.LstdFlags),
			NoColor: false,
		},
	)

	router.Use(middleware.Logger)

	contentStatic, err := fs.Sub(static, "static")
	if err != nil {
		panic(err)
	}

	httpFs := http.FS(contentStatic)
	fileServer := http.FileServer(httpFs)
	router.Handle("/static/*", http.StripPrefix("/static/", fileServer))
	loginKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		log.Panicf("secp256k1.GeneratePrivateKey(). %+v", err)
	}

	router.Get("/login", LoginGetHandler(serverData, false))
	router.Post("/login", LoginPostHandler(serverData, loginKey.Serialize()))

	if serverData.adminNpub != nil {
		router.Route("/admin", func(r chi.Router) {
			r.Get("/login", LoginGetHandler(serverData, true))
			r.Post("/login", LoginAdminPostHandler(serverData, loginKey.Serialize()))

			r.Group(func(r chi.Router) {
				r.Use(AuthAdminMiddleware(loginKey.Serialize(), serverData.adminNpub))
				r.Get("/", AdminDashboardHandler(serverData))

				r.Get("/add_npub_form", AddNpubDialogHandler())
				r.Post("/add_npub", PostAddNpubHandler(serverData))
			})
		})
	}

	// Group routes with specific middleware
	router.Group(func(r chi.Router) {
		r.Use(AuthMiddleware(loginKey.Serialize()))
		// Serve the dashboard at the root path and remove the separate /dashboard endpoint
		r.Get("/", DashboardHandler(serverData))
		r.Post("/createkey", CreateKeyHandler(serverData))

		// page for showing a dashboard for a signer
		r.Get("/signer/{id}", SignerDashboard(serverData))
		// API endpoint to update account name
		r.Put("/signer/{id}/name", UpdateAccountNameHandler(serverData))

		r.Get("/signer/{id}/keysets", KeysetsListHandler(serverData))

		// Certificate endpoints for HTMX requests: {which} is one of: ca, cert, key
		r.Get("/cert/{id}/{which}", CertHandler(serverData))
		// Download endpoint for certificates
		r.Get("/cert/{id}/{which}/download", CertDownloadHandler(serverData))
		// Hide endpoint to restore closed-eye button
		r.Get("/cert/{id}/{which}/hide", HideCertHandler(serverData))
		r.Post("/accounts/{id}/toggle-active", ToggleAccountActiveHandler(serverData))

	})

	return router
}

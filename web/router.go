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

	router.Get("/login", LoginGetHandler(serverData))
	router.Post("/login", LoginPostHandler(serverData, loginKey.Serialize()))

	// Group routes with specific middleware
	router.Group(func(r chi.Router) {
		r.Use(AuthMiddleware(loginKey.Serialize()))
		r.Get("/", DashboardHandler(serverData))
		r.Post("/createkey", CreateKeyHandler(serverData))
		r.Get("/signer/{id}", SignerDashboard(serverData))
		r.Put("/signer/{id}/name", UpdateAccountNameHandler(serverData))

		r.Get("/signer/{id}/keysets", KeysetsListHandler(serverData))

		r.Get("/cert/{id}/{which}", CertHandler(serverData))
		r.Get("/cert/{id}/{which}/download", CertDownloadHandler(serverData))
		r.Get("/cert/{id}/{which}/hide", HideCertHandler(serverData))
		r.Post("/accounts/{id}/toggle-active", ToggleAccountActiveHandler(serverData))
	})

	return router
}

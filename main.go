package main

import (
	"context"
	"io"
	"log"
	"log/slog"
	"net"
	accountmanager "nutmix_remote_signer/account_manager"
	"nutmix_remote_signer/database"
	sig "nutmix_remote_signer/gen"
	"nutmix_remote_signer/routes"
	"nutmix_remote_signer/signer"
	"nutmix_remote_signer/web"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"google.golang.org/grpc"
)

const abstractSocket = "@signer_socket"

func main() {
	err := godotenv.Load()
	if err != nil && !os.IsNotExist(err) {
		log.Panicf(`godotenv.Load(). %+v`, err)
	}

	homeDir, err := GetConfigDirectory()
	if err != nil {
		log.Panicf(`utils.GetRastaskerHomeDirectory(). %+v`, err)
	}

	logFile, err := os.OpenFile(homeDir+"logs", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Panicf("os.OpenFile(pathToProjectLogFile, os.O_RDWR|os.O_CREATE, 0764) %+v", err)
	}
	defer func() {
		_ = logFile.Close()
	}()

	w := io.MultiWriter(os.Stdout, logFile)

	opts := &slog.HandlerOptions{
		Level:       slog.LevelInfo,
		AddSource:   false,
		ReplaceAttr: nil,
	}

	if os.Getenv("DEBUG") == "true" {
		opts.Level = slog.LevelDebug
		opts.AddSource = true
	}

	logger := slog.New(slog.NewJSONHandler(w, opts))
	slog.SetDefault(logger)

	ctx := context.Background()
	sqlite, err := database.DatabaseSetup(ctx, homeDir)
	if err != nil {
		log.Panicf(`database.DatabaseSetup(ctx, "migrations"). %+v`, err)
	}
	defer func() {
		_ = sqlite.Db.Close()
	}()

	// get expirty time from env var if not use default
	var expiryTime *time.Time
	nowTime := time.Now()
	expiryHoursEnvStr := os.Getenv("KEYSET_EXPIRY_HOURS")
	if expiryHoursEnvStr != "" {
		expiryHoursEnv, err := strconv.ParseUint(expiryHoursEnvStr, 10, 64)
		if err != nil {
			slog.Warn("KEYSET_EXPIRY_HOURS is not set correctly. Using default of 720 hours.")
			nowTime = nowTime.Add(720 * time.Hour)
			expiryTime = &nowTime
		} else {
			nowTime = nowTime.Add(time.Duration(expiryHoursEnv) * time.Hour)
			expiryTime = &nowTime
		}
	}

	autoRotate, err := strconv.ParseBool(os.Getenv("AUTO_ROTATE"))
	if err != nil {
		autoRotate = false
	}

	config := signer.Config{
		ExpireTime: expiryTime,
		AutoRotate: autoRotate,
	}

	localSigner, err := signer.SetupLocalSigner(sqlite, config)
	if err != nil {
		log.Panicf(`signer.SetupLocalSigner(sqlite). %+v`, err)
	}

	manager := accountmanager.NewManager(&sqlite, localSigner)
	enableWebUI, err := strconv.ParseBool(getEnvOrDefault("ENABLE_WEB_UI", "false"))
	if err != nil {
		enableWebUI = false
	}
	if enableWebUI {
		caCertPath := getEnvOrDefault("TLS_CA_CERT_PATH", "tls/ca-cert.pem")
		caKeyPath := getEnvOrDefault("TLS_CA_KEY_PATH", "tls/ca-key.pem")
		caCertPEM, err := os.ReadFile(caCertPath)
		if err != nil {
			log.Panicf("os.ReadFile(%s). %+v", caCertPath, err)
		}
		caKeyPEM, err := os.ReadFile(caKeyPath)
		if err != nil {
			log.Panicf("os.ReadFile(%s). %+v", caKeyPath, err)
		}
		certDir := getEnvOrDefault("ACCOUNT_TLS_DIR", GetAccountCertificatesDir(homeDir))
		manager.ConfigureCertificates(caCertPEM, caKeyPEM, certDir)
		webAddr := getEnvOrDefault("WEB_UI_ADDR", "127.0.0.1:8080")
		go func() {
			if err := web.RunHTTPServer(webAddr, &manager); err != nil {
				slog.Error("failed to serve web ui", slog.Any("error", err))
			}
		}()
	}

	var listener net.Listener
	if os.Getenv("NETWORK") == "true" {
		// Create Unix listener
		slog.Info("Listening on network socket", slog.String("port", ":1721"))
		//nolint:gosec
		listener, err = net.Listen("tcp", ":1721")
		if err != nil {
			slog.Error("Error creating Unix socket:", slog.Any("error", err))
			return
		}
	} else {
		// Create Unix listener
		slog.Info("Listening on abstract socket", slog.String("port", abstractSocket))
		listener, err = net.Listen("unix", abstractSocket)
		if err != nil {
			slog.Error("Error creating Unix socket:", slog.Any("error", err))
			return
		}

	}

	creds := GetTlsSecurityCredential()

	// Create a new gRPC server
	s := grpc.NewServer(grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(routes.SchemaVersion(), routes.AuthMiddleware(sqlite)))

	// Register the service
	sig.RegisterSignatoryServer(s, &routes.Server{
		Signer:          localSigner,
		SignatoryServer: nil,
	})

	// Serve gRPC requests
	if err := s.Serve(listener); err != nil {
		slog.Error("failed to serve:", slog.Any("error", err))
		return
	}
}

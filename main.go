package main

import (
	"context"
	"io"
	"log"
	"log/slog"
	"net"
	"nutmix_remote_signer/database"
	sig "nutmix_remote_signer/gen"
	"nutmix_remote_signer/routes"
	"nutmix_remote_signer/signer"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"google.golang.org/grpc"
)

const abstractSocket = "@signer_socket"

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Panicf(`godotenv.Load(). %+v`, err)
	}

	homeDir, err := GetConfigDirectory()
	if err != nil {
		log.Panicf(`utils.GetRastaskerHomeDirectory(). %+v`, err)
	}

	logFile, err := os.OpenFile(homeDir+"logs", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0764)
	if err != nil {
		log.Panicf("os.OpenFile(pathToProjectLogFile, os.O_RDWR|os.O_CREATE, 0764) %+v", err)
	}
	defer logFile.Close()

	w := io.MultiWriter(os.Stdout, logFile)

	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
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
	defer sqlite.Db.Close()

	// get expirty time from env var if not use default
	expiryTime := time.Now()
	expiryHoursEnvStr := os.Getenv("KEYSET_EXPIRY_HOURS")
	if expiryHoursEnvStr != "" {
		expiryHoursEnv , err := strconv.ParseUint(expiryHoursEnvStr, 10,64)
		if err != nil {
			slog.Warn("KEYSET_EXPIRY_HOURS is not set correctly. Using default of 720 hours.")
			expiryTime = expiryTime.Add(720 * time.Hour)
		} else {
			expiryTime = expiryTime.Add(time.Duration(expiryHoursEnv) * time.Hour)
		}
	}


	signer, err := signer.SetupLocalSigner(sqlite, expiryTime)
	if err != nil {
		log.Panicf(`signer.SetupLocalSigner(sqlite). %+v`, err)
	}

	var listener net.Listener
	if os.Getenv("NETWORK") == "true" {
		// Create Unix listener
		slog.Info("Listening on network socket", slog.String("port", ":1721"))
		listener, err = net.Listen("tcp", ":1721")
		if err != nil {
			log.Fatal("Error creating Unix socket:", err)
		}
	} else {
		// Create Unix listener
		slog.Info("Listening on abstract socket", slog.String("port", abstractSocket))
		listener, err = net.Listen("unix", abstractSocket)
		if err != nil {
			log.Fatal("Error creating Unix socket:", err)
		}


	}

	creds, err := GetTlsSecurityCredential()
	if err != nil {
		log.Fatalf("Error creating Unix socket: %+v", err)
	}

	// Create a new gRPC server
	s := grpc.NewServer(grpc.Creds(creds))

	// Register the service
	sig.RegisterSignerServiceServer(s, &routes.Server{
		Signer: signer,
	})

	// Serve gRPC requests
	if err := s.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

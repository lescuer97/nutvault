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

	"github.com/joho/godotenv"
	"google.golang.org/grpc"
)

const socketPath = "/tmp/signer.sock"
const abstractSocket = "@signer_socket"

func main() {
	// Clean up previous socket
	if _, err := os.Stat(socketPath); err == nil {
		if err := os.Remove(socketPath); err != nil {
			log.Fatal("Error removing existing socket:", err)
		}
	}
	err := godotenv.Load()
	if err != nil {
		log.Panicf(`godotenv.Load(). %+v`, err)
	}

	homeDir, err := GetHomeDirectory()
	if err != nil {
		log.Panicf(`utils.GetRastaskerHomeDirectory(). %+v`, err)
	}

	logFile, err := os.OpenFile(homeDir+"logs", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0764)
	defer logFile.Close()
	if err != nil {
		log.Panicf("os.OpenFile(pathToProjectLogFile, os.O_RDWR|os.O_CREATE, 0764) %+v", err)
	}

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
	defer sqlite.Db.Close()

	if err != nil {
		log.Panicf(`database.DatabaseSetup(ctx, "migrations"). %+v`, err)
	}

	signer, err := signer.SetupLocalSigner(sqlite)
	if err != nil {
		log.Panicf(`signer.SetupLocalSigner(sqlite). %+v`, err)
	}

	// Create Unix listener
	listener, err := net.Listen("unix", abstractSocket)
	if err != nil {
		log.Fatal("Error creating Unix socket:", err)
	}

	creds, err := GetTlsSecurityCredential()
	if err != nil {
		log.Fatalf("Error creating Unix socket: %+v", err)
	}

	slog.Info("Listening on unix socket: %s", abstractSocket)
	// Create a new gRPC server
	s := grpc.NewServer(grpc.Creds(creds))

	// logger.D
	// Register the service
	sig.RegisterSignerServiceServer(s, &routes.Server{
		Signer: signer,
	})

	// Serve gRPC requests
	if err := s.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

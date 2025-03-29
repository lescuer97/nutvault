package main

import (
	"context"
	"log"
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

	log.Printf("Listening on unix socket: %s", abstractSocket)
	// Create a new gRPC server
	s := grpc.NewServer(grpc.Creds(creds))

	// Register the service
	sig.RegisterSignerServer(s, &routes.Server{
		Signer: signer,
	})

	log.Printf("Server listening on unix socket: %s", abstractSocket)

	// Serve gRPC requests
	if err := s.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

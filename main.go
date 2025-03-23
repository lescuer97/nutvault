package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"nutmix_remote_signer/database"
	"nutmix_remote_signer/routes"
	"nutmix_remote_signer/signer"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
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

	router := gin.Default()
	signer, err := signer.SetupLocalSigner(sqlite)
	if err != nil {
		log.Panicf(`signer.SetupLocalSigner(sqlite). %+v`, err)
	}

	routes.Routes(router,signer )
	// Create Unix listener
	listener, err := net.Listen("unix", abstractSocket)
	if err != nil {
		log.Fatal("Error creating Unix socket:", err)
	}

	log.Printf("Listening on unix socket: %s", abstractSocket)
	http.Serve(listener, router)
}

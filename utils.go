package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"

	"google.golang.org/grpc/credentials"
)

const NutvaultName = ".nutvault"

func GetConfigDirectory() (string, error) {

	homedir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("os.UserConfigDir(). %w", err)
	}

	rataskerDir := homedir + "/" + NutvaultName
	err = MakeSureFilePathExists(rataskerDir, "")
	if err != nil {
		return "", fmt.Errorf("MakeSureFilePathExists(rataskerDir ). %w", err)
	}

	return rataskerDir, nil
}

func MakeSureFilePathExists(dirPath string, filename string) error {

	completeFilePath := dirPath + "/" + filename

	_, err := os.Stat(dirPath)

	if os.IsNotExist(err) {
		err = os.MkdirAll(dirPath, 0764)
		if err != nil {
			return fmt.Errorf("os.MkdirAll(pathToProjectDir, 0764) %w", err)
		}
	}

	_, err = os.Stat(completeFilePath)

	if os.IsNotExist(err) {
		_, err := os.Create(completeFilePath)
		if err != nil {
			return fmt.Errorf("os.Create(pathToProjectConfigFile) %w", err)
		}
	}

	return nil

}

func GetTlsSecurityCredential() (credentials.TransportCredentials, error) {
	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair("tls/server-cert.pem", "tls/server-key.pem")
	if err != nil {
		log.Fatalf("Failed to load server cert: %v", err)
	}

	// Load CA certificate
	caCert, err := os.ReadFile("tls/ca-cert.pem")
	if err != nil {
		log.Fatalf("Failed to load CA cert: %v", err)
	}

	// Create a certificate pool and add the CA certificate
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		log.Fatal("Failed to add CA certificate to pool")
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert, // Require client certificate
		ClientCAs:    certPool,                 // Verify client certificate against this CA
	}

	// Create the TLS credentials
	creds := credentials.NewTLS(tlsConfig)
	return creds, nil

}

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"google.golang.org/grpc/credentials"
)

const NutvaultName = "nutvault"

func GetConfigDirectory() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("os.UserConfigDir(). %w", err)
	}

	rataskerDir := configDir + "/" + NutvaultName
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
		err = os.MkdirAll(dirPath, 0750)
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

func GetTlsSecurityCredential() credentials.TransportCredentials {
	serverCertPath := getEnvOrDefault("TLS_SERVER_CERT_PATH", "tls/server-cert.pem")
	serverKeyPath := getEnvOrDefault("TLS_SERVER_KEY_PATH", "tls/server-key.pem")
	caCertPath := getEnvOrDefault("TLS_CA_CERT_PATH", "tls/ca-cert.pem")
	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		log.Fatalf("Failed to load server cert: %v", err)
	}

	// Load CA certificate
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Fatalf("Failed to load CA cert: %v", err)
	}

	// Create a certificate pool and add the CA certificate
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		log.Fatal("Failed to add CA certificate to pool")
	}

	// Create TLS configuration
	// nolint:exhaustruct
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert, // Require client certificate
		ClientCAs:    certPool,                       // Verify client certificate against this CA
	}

	// Create the TLS credentials
	creds := credentials.NewTLS(tlsConfig)
	return creds

}

func getEnvOrDefault(envKey string, fallback string) string {
	value := os.Getenv(envKey)
	if value == "" {
		return fallback
	}
	return value
}

func GetAccountCertificatesDir(configDir string) string {
	return filepath.Join(configDir, "certificates")
}

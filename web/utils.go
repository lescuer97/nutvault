package web

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/http"
	"nutmix_remote_signer/database"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/go-chi/chi/v5"
)

var ErrNpubDoesNotOwnSignerId = errors.New("Npub does not own signer")

func VerifyIdInRequestIsAvailable(serverData *ServerData, request *http.Request) (*database.IndividualKey, error) {
	id := chi.URLParam(request, "id")
	if serverData == nil {
		log.Panicf("Server data should not be nil ever at this point")
	}
	if serverData.manager == nil {
		log.Panicf("Manager should never be null at this point")
	}

	if err := sanitizeId(id); err != nil {
		return nil, fmt.Errorf("sanitizeId(id). %w", err)
	}

	// Ownership verification (same pattern as other handlers)
	account, err := serverData.manager.GetKeyById(id)
	if err != nil {
		return nil, fmt.Errorf("serverData.manager.GetAccountById(id). %w", err)
	}

	audPub, err := GetAudience(request)
	if err != nil {
		return nil, fmt.Errorf("GetAudience(request). %w", err)
	}
	if !bytes.Equal(audPub.SerializeCompressed(), account.Npub) {
		return nil, ErrNpubDoesNotOwnSignerId
	}

	return account, nil
}
func sanitizeId(id string) error {
	if id == "" {
		return errors.New("empty id")
	}
	// validate hex length 64
	if err := validate.Var(id, "required,len=64,hexadecimal"); err != nil {
		return err
	}
	return nil
}

func sanitizeWhich(which string) (string, error) {
	// use validator oneof for allowed values
	if err := validate.Var(which, "required,oneof=ca cert key"); err != nil {
		return "", err
	}
	return allowedWhich[which], nil
}

// ensure the resolved file path stays within baseDir to prevent directory traversal
func safeJoinFile(baseDir, fileName string) (string, error) {
	if strings.Contains(fileName, "..") || strings.ContainsAny(fileName, "/\\") {
		return "", errors.New("invalid filename")
	}
	joined := filepath.Join(baseDir, fileName)
	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}
	// ensure trailing separator on base for prefix check
	baseWithSep := absBase
	if !strings.HasSuffix(baseWithSep, string(os.PathSeparator)) {
		baseWithSep = baseWithSep + string(os.PathSeparator)
	}
	if !strings.HasPrefix(absJoined, baseWithSep) {
		return "", errors.New("path escapes base directory")
	}
	return absJoined, nil
}

// sanitizeFileName makes a safe short filename from an account name
func sanitizeFileName(name string) string {
	if name == "" {
		return "account"
	}
	// replace spaces with underscores
	name = strings.ReplaceAll(name, " ", "_")
	// map to allowed chars: letters, digits, '-', '_', '.'
	mapped := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, name)
	// trim length
	if len(mapped) > 200 {
		mapped = mapped[:200]
	}
	return mapped
}

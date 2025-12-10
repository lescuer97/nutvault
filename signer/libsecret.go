package signer

import (
	"encoding/hex"
	"errors"
	"fmt"

	goLibSecret "github.com/lescuer97/go-libsecret"
)

const Service = "nutvault"
const masterKey = "master-key"
const SchemaName = "org.app.Nutvault"

var (
	ErrNotFound    = errors.New("Could not found value in keystore")
	SchemaNotSetup = errors.New("Main schema was not setup you need that first")
)

var mainSchema *goLibSecret.Schema

func SetupKeychain() error {
	attr := map[string]goLibSecret.SchemaAttributeType{
		"key": goLibSecret.SchemaAttributeString,
	}

	schema, err := goLibSecret.NewSchema(SchemaName, goLibSecret.SchemaFlagsNone, attr)
	if err != nil {
		return fmt.Errorf("goLibSecret.NewSchema(SchemaName). %w", err)

	}

	mainSchema = schema
	return nil
}

func GetNutmixSignerKey() (string, error) {
	key, err := getSecret(masterKey)
	if err != nil {
		return "", fmt.Errorf("getSecret(masterKey). %w", err)

	}
	return string(key), nil
}

func StoreSeedPhrase(mnemonic string) error {
	return setSecret(masterKey, []byte(mnemonic))
}

func setSecret(id string, secret []byte) error {
	if mainSchema == nil {
		return SchemaNotSetup
	}

	attr := map[string]string{
		"key": id,
	}

	return goLibSecret.StorePassword(mainSchema, attr, goLibSecret.CollectionDefault, SchemaName, hex.EncodeToString(secret))
}

func getSecret(id string) ([]byte, error) {
	if mainSchema == nil {
		return nil, SchemaNotSetup
	}
	attrs := goLibSecret.NewAttributes()
	attrs.Set("key", id)

	val, err := goLibSecret.PasswordLookupSync(mainSchema, attrs)
	if err != nil {
		return nil, fmt.Errorf("goLibSecret.PasswordLookupSync(mainSchema, attrs). %w", err)
	}
	if val == "" {
		return nil, ErrNotFound
	}

	secret, err := hex.DecodeString(val)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString(). %w", err)
	}
	return secret, nil
}

package signer

import (
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
	return key, nil
}

func StoreSeedPhrase(mnemonic string) error {
	return setSecret(masterKey,mnemonic)
}

func setSecret(id string, secret string) error {
	if mainSchema == nil {
		return SchemaNotSetup
	}

	attr := map[string]string{
		"key": id,
	}

	return goLibSecret.StorePassword(mainSchema, attr, goLibSecret.CollectionDefault, SchemaName, secret)
}

func getSecret(id string) (string, error) {
	if mainSchema == nil {
		return "", SchemaNotSetup
	}
	attrs := goLibSecret.NewAttributes()
	attrs.Set("key", id)

	val, err := goLibSecret.PasswordLookupSync(mainSchema, attrs)
	if err != nil {
		return "", fmt.Errorf("goLibSecret.PasswordLookupSync(mainSchema, attrs). %w", err)
	}
	if val == "" {
		return "", ErrNotFound
	}

	return val, nil
}

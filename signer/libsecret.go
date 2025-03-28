package signer

import (
	"fmt"
	"log"
	"os"

	"github.com/godbus/dbus/v5"
)

func GetDbusConnection() {

}

type SecretStructure struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// GetNutmixSignerKey retrieves the secret key for the nutmix-remote-signer application
// from the system's secret service (libsecret) via DBus
func GetNutmixSignerKey() (string, error) {
	// Connect to the session bus
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return "", fmt.Errorf("failed to connect to session bus: %v", err)
	}
	defer conn.Close()

	// Get the Secret Service object
	secretService := conn.Object("org.freedesktop.secrets", "/org/freedesktop/secrets")

	// Get the default collection
	var defaultCollection dbus.ObjectPath
	err = secretService.Call("org.freedesktop.Secret.Service.ReadAlias", 0, "default").Store(&defaultCollection)
	if err != nil {
		return "", fmt.Errorf("failed to get default collection: %v", err)
	}

	// Create the collection object
	collection := conn.Object("org.freedesktop.secrets", defaultCollection)

	// Create search attributes for our app
	searchAttributes := map[string]string{
		"application": "nutmix-remote-signer",
	}

	// Search for items matching our criteria
	var resultItems []dbus.ObjectPath
	err = collection.Call("org.freedesktop.Secret.Collection.SearchItems", 0, searchAttributes).Store(&resultItems)
	if err != nil {
		return "", fmt.Errorf("failed to search items: %v", err)
	}

	// Create a session for secret transfer
	var openSession dbus.ObjectPath
	var sessionAlgorithm string
	err = secretService.Call("org.freedesktop.Secret.Service.OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&sessionAlgorithm, &openSession)
	if err != nil {
		return "", fmt.Errorf("failed to open session: %v", err)
	}

	// If we have a result, get the existing secret
	if len(resultItems) > 0 {
		// Get the first item
		item := conn.Object("org.freedesktop.secrets", resultItems[0])

		// Get the secret
		var secretStruct SecretStructure

		err = item.Call("org.freedesktop.Secret.Item.GetSecret", 0, openSession).Store(&secretStruct)
		if err != nil {
			return "", fmt.Errorf("failed to get secret: %v", err)
		}

		log.Println("returning from the storage")
		// Convert the secret value to a string
		secretValue := string(secretStruct.Value)
		return secretValue, nil
	}

	mint_privkey := os.Getenv("MINT_PRIVATE_KEY")
	if mint_privkey == "" {
		return "", fmt.Errorf(`os.Getenv("MINT_PRIVATE_KEY").`)
	}

	if mint_privkey == "" {
		panic("private key for the mint is not set for storage")
	}
	properties := map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label": dbus.MakeVariant("Nutmix Remote Signer Key"),
		"org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(map[string]string{
			"application": "nutmix-remote-signer",
			"type":        "api-key",
		}),
	}
	// Prepare the secret structure
	secret := SecretStructure{
		Session:     openSession,
		Parameters:  []byte{},
		Value:       []byte(mint_privkey),
		ContentType: "text/plain",
	}

	// Create the new item with the secret
	var newItem dbus.ObjectPath
	err = collection.Call(
		"org.freedesktop.Secret.Item.SetSecret",
		0,
		properties,
		secret,
		true, // Replace if exists
	).Store(&newItem)

	if err != nil {
		return "", fmt.Errorf("failed to store new secret: %v", err)
	}

	return mint_privkey, nil
}

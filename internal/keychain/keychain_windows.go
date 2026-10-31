//go:build windows

package keychain

import (
	"fmt"

	"github.com/danieljoos/wincred"
)

const credTarget = "sync-vault"

func StorePassphrase(passphrase string) error {
	cred := wincred.NewGenericCredential(credTarget + entrySuffix())
	cred.CredentialBlob = []byte(passphrase)
	return cred.Write()
}

func LoadPassphrase() (string, error) {
	cred, err := wincred.GetGenericCredential(credTarget + entrySuffix())
	if err != nil {
		return "", fmt.Errorf("passphrase not found in Windows Credential Manager (%q): run 'vault-mcp init' first", credTarget+entrySuffix())
	}
	return string(cred.CredentialBlob), nil
}

func DeletePassphrase() error {
	cred, err := wincred.GetGenericCredential(credTarget + entrySuffix())
	if err != nil {
		return nil // already gone
	}
	return cred.Delete()
}

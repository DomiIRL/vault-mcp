//go:build windows

package keychain

import (
	"fmt"

	"github.com/danieljoos/wincred"
)

const credTarget = "sync-vault"

func StorePassphrase(passphrase string) error {
	cred := wincred.NewGenericCredential(credTarget)
	cred.CredentialBlob = []byte(passphrase)
	return cred.Write()
}

func LoadPassphrase() (string, error) {
	cred, err := wincred.GetGenericCredential(credTarget)
	if err != nil {
		return "", fmt.Errorf("passphrase not found in Windows Credential Manager (%q): run 'vault-mcp init' first", credTarget)
	}
	return string(cred.CredentialBlob), nil
}

func DeletePassphrase() error {
	cred, err := wincred.GetGenericCredential(credTarget)
	if err != nil {
		return nil // already gone
	}
	return cred.Delete()
}

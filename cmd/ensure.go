package cmd

import (
	"fmt"
	"os"

	"github.com/DomiIRL/vault-mcp/internal/keychain"
	"github.com/DomiIRL/vault-mcp/internal/vault"
)

// ensureUnlocked returns the vault passphrase, running first-time setup if needed.
// All credential-requiring commands call this instead of keychain.LoadPassphrase directly.
func ensureUnlocked() (string, error) {
	pass, err := keychain.LoadPassphrase()
	if err == nil {
		return pass, nil
	}

	if _, statErr := os.Stat(vault.VaultPath()); os.IsNotExist(statErr) {
		return runFirstTimeSetup()
	}
	return registerMachine()
}

// runFirstTimeSetup handles the very first machine — no vault.age exists yet.
func runFirstTimeSetup() (string, error) {
	fmt.Fprintln(os.Stderr, "No vault found. Running first-time setup.")
	fmt.Fprintln(os.Stderr, "Choose a master passphrase — you will need it when registering future machines.")
	fmt.Fprintln(os.Stderr, "")

	pass, err := promptPassphrase("Master passphrase: ")
	if err != nil {
		return "", err
	}
	confirm, err := promptPassphrase("Confirm passphrase: ")
	if err != nil {
		return "", err
	}
	if pass != confirm {
		return "", fmt.Errorf("passphrases do not match")
	}

	fmt.Fprintln(os.Stderr, "Storing in keychain…")
	if err := keychain.StorePassphrase(pass); err != nil {
		return "", fmt.Errorf("keychain: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Creating vault…")
	if err := vault.Init(pass); err != nil {
		return "", fmt.Errorf("create vault: %w", err)
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Done. vault.age can be committed to git or synced however you like; the passphrase never is.")
	return pass, nil
}

// registerMachine handles a machine that has vault.age (synced from git) but no keychain entry.
func registerMachine() (string, error) {
	fmt.Fprintln(os.Stderr, "Vault found but this machine is not registered yet.")
	fmt.Fprintln(os.Stderr, "Enter the master passphrase to register:")
	fmt.Fprintln(os.Stderr, "")

	pass, err := promptPassphrase("Master passphrase: ")
	if err != nil {
		return "", err
	}

	if _, err := vault.Load(pass); err != nil {
		return "", fmt.Errorf("wrong passphrase — could not decrypt vault")
	}

	if err := keychain.StorePassphrase(pass); err != nil {
		return "", fmt.Errorf("store in keychain: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Registered. This machine is ready.")
	return pass, nil
}

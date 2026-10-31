//go:build !windows

package keychain

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/zalando/go-keyring"
)

const (
	ringService = "sync-vault"
	ringUser    = "passphrase"
	// Legacy secret-tool attributes used before go-keyring migration.
	legacyAttr  = "application"
	legacyValue = "sync-vault"
)

func StorePassphrase(passphrase string) error {
	if err := keyring.Set(ringService, ringUser+entrySuffix(), passphrase); err == nil {
		return nil
	}
	return storeFile(passphrase)
}

func LoadPassphrase() (string, error) {
	pass, err := keyring.Get(ringService, ringUser+entrySuffix())
	if err == nil {
		return pass, nil
	}
	if entrySuffix() != "" {
		return loadFile()
	}

	// Migrate from old secret-tool storage (Linux) or security CLI (macOS).
	pass, migrateErr := loadLegacy()
	if migrateErr != nil {
		return loadFile()
	}

	// Re-store under new key and clear old one.
	_ = keyring.Set(ringService, ringUser, pass)
	clearLegacy()
	return pass, nil
}

func DeletePassphrase() error {
	_ = keyring.Delete(ringService, ringUser+entrySuffix())
	if entrySuffix() == "" {
		clearLegacy()
	}
	return deleteFile()
}

// loadLegacy retrieves the passphrase from the old storage (secret-tool on
// Linux, security CLI on macOS). Used only during one-time migration.
func loadLegacy() (string, error) {
	var out []byte
	var err error

	// Try Linux secret-tool first, then macOS security.
	out, err = exec.Command("secret-tool", "lookup", legacyAttr, legacyValue).Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return strings.TrimSpace(string(out)), nil
	}

	out, err = exec.Command("security", "find-generic-password",
		"-a", legacyValue, "-s", legacyValue, "-w").Output()
	if err == nil {
		return strings.TrimSpace(string(out)), nil
	}

	return "", fmt.Errorf("no legacy credential found")
}

// clearLegacy removes the passphrase from the old storage backends.
func clearLegacy() {
	_ = exec.Command("secret-tool", "clear", legacyAttr, legacyValue).Run()
	_ = exec.Command("security", "delete-generic-password",
		"-a", legacyValue, "-s", legacyValue).Run()
}

func fallbackPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "sync-vault", "master")
}

func storeFile(passphrase string) error {
	path := fallbackPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(passphrase), 0600)
}

func loadFile() (string, error) {
	data, err := os.ReadFile(fallbackPath())
	if err != nil {
		return "", fmt.Errorf("passphrase not found in keychain or fallback file (%s): run 'vault-mcp init' first", fallbackPath())
	}
	return strings.TrimSpace(string(data)), nil
}

func deleteFile() error {
	err := os.Remove(fallbackPath())
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

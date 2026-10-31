package keychain

import (
	"os"
	"path/filepath"
)

// entrySuffix keys the stored passphrase by VAULT_ROOT, so a second vault keeps its own
// passphrase next to the default one. The default root keeps the unsuffixed entry.
func entrySuffix() string {
	r := os.Getenv("VAULT_ROOT")
	if r == "" {
		return ""
	}
	if abs, err := filepath.Abs(r); err == nil {
		r = abs
	}
	return ":" + r
}

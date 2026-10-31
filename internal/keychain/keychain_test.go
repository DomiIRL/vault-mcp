package keychain

import (
	"path/filepath"
	"testing"
)

func TestEntrySuffixDefaultRoot(t *testing.T) {
	t.Setenv("VAULT_ROOT", "")
	if got := entrySuffix(); got != "" {
		t.Fatalf("default root must keep the unsuffixed entry, got %q", got)
	}
}

func TestEntrySuffixIsAbsolute(t *testing.T) {
	t.Setenv("VAULT_ROOT", "agents/alice")
	abs, _ := filepath.Abs("agents/alice")
	if got := entrySuffix(); got != ":"+abs {
		t.Fatalf("got %q, want %q", got, ":"+abs)
	}
}

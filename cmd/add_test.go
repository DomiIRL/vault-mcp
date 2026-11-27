package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/DomiIRL/vault-mcp/internal/keychain"
	"github.com/DomiIRL/vault-mcp/internal/vault"
	"github.com/zalando/go-keyring"
)

const testPass = "test-passphrase"

func newTestVault(t *testing.T) {
	t.Helper()
	keyring.MockInit()
	t.Setenv("VAULT_ROOT", t.TempDir())
	if err := keychain.StorePassphrase(testPass); err != nil {
		t.Fatal(err)
	}
	if err := vault.Init(testPass); err != nil {
		t.Fatal(err)
	}
}

func pipedAdd(t *testing.T, input string, args ...string) error {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(input); err != nil {
		t.Fatal(err)
	}
	w.Close()

	stdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = stdin; r.Close() })

	addForce = false
	rootCmd.SetArgs(append([]string{"add"}, args...))
	return rootCmd.Execute()
}

func stored(t *testing.T) string {
	t.Helper()
	v, err := vault.Load(testPass)
	if err != nil {
		t.Fatal(err)
	}
	return v.Secrets["zone/svc"]["KEY"]
}

func TestAddPipedSecretDropsTrailingNewlines(t *testing.T) {
	for _, input := range []string{"s3cret value", "s3cret value\n", "s3cret value\r\n", "\xef\xbb\xbfs3cret value\n"} {
		newTestVault(t)
		if err := pipedAdd(t, input, "zone/svc", "KEY"); err != nil {
			t.Fatalf("%q: %v", input, err)
		}
		if got := stored(t); got != "s3cret value" {
			t.Errorf("%q stored as %q", input, got)
		}
	}
}

func TestAddPipedSecretRefusesBadInput(t *testing.T) {
	for _, input := range []string{"", "\n", "first\nsecond\n"} {
		newTestVault(t)
		if err := pipedAdd(t, input, "zone/svc", "KEY"); err == nil {
			t.Errorf("%q: expected an error", input)
		}
		if got := stored(t); got != "" {
			t.Errorf("%q stored as %q", input, got)
		}
	}
}

func TestAddPipedOverwriteNeedsForce(t *testing.T) {
	newTestVault(t)
	if err := pipedAdd(t, "old", "zone/svc", "KEY"); err != nil {
		t.Fatal(err)
	}

	err := pipedAdd(t, "new", "zone/svc", "KEY")
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("expected a --force error, got %v", err)
	}
	if got := stored(t); got != "old" {
		t.Errorf("stored %q without --force", got)
	}

	if err := pipedAdd(t, "new", "--force", "zone/svc", "KEY"); err != nil {
		t.Fatal(err)
	}
	if got := stored(t); got != "new" {
		t.Errorf("stored %q with --force", got)
	}
}

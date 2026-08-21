package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/DomiIRL/vault-mcp/internal/vault"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Force first-time vault setup (normally runs automatically on first use)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := os.Stat(vault.VaultPath()); err == nil {
			// Vault already exists — this is a new machine registering.
			// ensureUnlocked handles this path automatically on any command,
			// but allow explicit 'vault-mcp init' to do the same.
			_, err := registerMachine()
			return err
		}
		_, err := runFirstTimeSetup()
		return err
	},
}

func promptPassphrase(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", errors.New("passphrase cannot be empty")
	}
	return string(b), nil
}

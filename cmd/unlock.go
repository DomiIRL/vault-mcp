package cmd

import (
	"fmt"
	"os"

	"github.com/DomiIRL/vault-mcp/internal/vault"
	"github.com/spf13/cobra"
)

var unlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Decrypt vault to <root>/decrypted/ (human use)",
	RunE: func(cmd *cobra.Command, args []string) error {
		pass, err := ensureUnlocked()
		if err != nil {
			return err
		}

		v, err := vault.Load(pass)
		if err != nil {
			return err
		}

		if err := v.WriteDecrypted(); err != nil {
			return fmt.Errorf("write decrypted: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Unlocked %d service(s) → %s\n", len(v.Services()), vault.DecryptedPath())
		return nil
	},
}

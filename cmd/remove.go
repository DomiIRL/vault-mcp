package cmd

import (
	"fmt"
	"os"

	"github.com/DomiIRL/vault-mcp/internal/vault"
	"github.com/spf13/cobra"
)

var removeCmd = &cobra.Command{
	Use:   "remove <zone/service> <KEY>",
	Short: "Remove a secret from the vault",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		service, key := args[0], args[1]

		pass, err := ensureUnlocked()
		if err != nil {
			return err
		}

		v, err := vault.Load(pass)
		if err != nil {
			return err
		}

		if !v.Delete(service, key) {
			return fmt.Errorf("key %q not found in %s", key, service)
		}

		if err := vault.Save(pass, v); err != nil {
			return fmt.Errorf("save vault: %w", err)
		}
		if err := vault.UpdateIndex(v); err != nil {
			return fmt.Errorf("update index: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Removed %s/%s.\n", service, key)
		return nil
	},
}

package cmd

import (
	"fmt"
	"os"

	"github.com/DomiIRL/vault-mcp/internal/vault"
	"github.com/spf13/cobra"
)

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Securely delete <root>/decrypted/",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := vault.RemoveDecrypted(); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Vault locked.")
		return nil
	},
}

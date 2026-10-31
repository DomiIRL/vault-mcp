package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "vault-mcp",
	Short: "Encrypted secrets vault with an MCP server for AI coding agents",
	Long: `vault manages secrets in a single age-encrypted file at ~/.vault/vault.age
(override the directory with VAULT_ROOT).

Values are never printed, never passed as CLI arguments, and never handed to an
AI agent. Agents use the vault through the 'ssh' and 'exec' proxy commands, and
tool output is scrubbed of every secret value before they see it.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(
		initCmd,
		unlockCmd,
		lockCmd,
		addCmd,
		removeCmd,
		mvCmd,
		listCmd,
		migrateCmd,
		passwdCmd,
		sshCmd,
		execCmd,
	)
}

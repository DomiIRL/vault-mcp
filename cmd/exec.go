package cmd

import (
	"fmt"
	"os"

	"github.com/DomiIRL/vault-mcp/internal/vault"
	"github.com/spf13/cobra"
)

var execCmd = &cobra.Command{
	Use:                "exec <zone/service> -- <command> [args...]",
	Short:              "Run a command with service secrets injected as env vars",
	Args:               cobra.MinimumNArgs(3),
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 3 || args[1] != "--" {
			return fmt.Errorf("usage: vault-mcp exec <zone/service> -- <command> [args...]")
		}
		service, cmdArgs := args[0], args[2:]

		pass, err := ensureUnlocked()
		if err != nil {
			return err
		}
		s, err := vault.Load(pass)
		if err != nil {
			return err
		}
		env, err := s.ServiceEnv(service)
		if err != nil {
			return err
		}
		return vault.RunExec(env, cmdArgs, os.Stdout, os.Stderr, os.Stdin)
	},
}

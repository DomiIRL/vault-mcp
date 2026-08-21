package cmd

import (
	"fmt"
	"os"

	"github.com/DomiIRL/vault-mcp/internal/vault"
	"github.com/spf13/cobra"
)

var sshCmd = &cobra.Command{
	Use:                "ssh <zone/service> [--sudo] -- <remote-command> [args...]",
	Short:              "SSH proxy — credentials injected from vault, never exposed",
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("usage: vault-mcp ssh <zone/service> -- <command>")
		}
		sudo, args := extractFlag(args, "--sudo")
		service, remoteArgs := splitDashDash(args)
		if len(remoteArgs) == 0 {
			return fmt.Errorf("interactive sessions are not supported\nusage: vault-mcp ssh %s -- <command>", service)
		}

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
		if sudo {
			sudoCmd := "sudo -S -p '' -- " + vault.ShellJoin(remoteArgs)
			return vault.RunSSHWithStdin(env, sudoCmd, env["SSH_PASSWORD"]+"\n", os.Stdout, os.Stderr)
		}
		return vault.RunSSH(env, vault.ShellJoin(remoteArgs), os.Stdout, os.Stderr)
	},
}

// extractFlag removes the first occurrence of flag from args (only before "--")
// and returns whether it was present along with the cleaned args slice.
func extractFlag(args []string, flag string) (bool, []string) {
	dashDash := len(args)
	for i, a := range args {
		if a == "--" {
			dashDash = i
			break
		}
	}
	for i := 0; i < dashDash; i++ {
		if args[i] == flag {
			return true, append(args[:i:i], args[i+1:]...)
		}
	}
	return false, args
}

func splitDashDash(args []string) (string, []string) {
	service := args[0]
	for i, a := range args {
		if a == "--" {
			return service, args[i+1:]
		}
	}
	return service, nil
}

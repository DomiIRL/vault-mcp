package cmd

import (
	"fmt"
	"os"
	"sort"

	"github.com/DomiIRL/vault-mcp/internal/vault"
	"github.com/spf13/cobra"
)

var mvCmd = &cobra.Command{
	Use:   "mv <zone/service> <new-name>",
	Short: "Rename a service, or every service under a prefix ending in /",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		pass, err := ensureUnlocked()
		if err != nil {
			return err
		}

		v, err := vault.Load(pass)
		if err != nil {
			return err
		}

		moves, err := v.Rename(args[0], args[1])
		if err != nil {
			return err
		}

		if err := vault.Save(pass, v); err != nil {
			return fmt.Errorf("save vault: %w", err)
		}
		if err := vault.UpdateIndex(v); err != nil {
			return fmt.Errorf("update index: %w", err)
		}

		srcs := make([]string, 0, len(moves))
		for src := range moves {
			srcs = append(srcs, src)
		}
		sort.Strings(srcs)
		for _, src := range srcs {
			fmt.Fprintf(os.Stderr, "%s -> %s\n", src, moves[src])
		}
		return nil
	},
}

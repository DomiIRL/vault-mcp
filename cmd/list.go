package cmd

import (
	"fmt"
	"sort"

	"github.com/DomiIRL/vault-mcp/internal/vault"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list [zone/service]",
	Short: "List keys in the vault — property values are shown, secret values never are",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		vpass, err := ensureUnlocked()
		if err != nil {
			return err
		}

		v, err := vault.Load(vpass)
		if err != nil {
			return err
		}

		if len(args) == 1 {
			service := args[0]
			if _, err := v.ServiceEnv(service); err != nil {
				return err
			}
			for _, line := range serviceLines(v, service) {
				fmt.Println(line)
			}
			return nil
		}

		for _, svc := range v.Services() {
			fmt.Println(svc)
			for _, line := range serviceLines(v, svc) {
				fmt.Println("  " + line)
			}
		}
		return nil
	},
}

// serviceLines renders one service: properties with their value, secrets by name.
func serviceLines(v *vault.Vault, service string) []string {
	var lines []string
	for k, val := range v.Properties[service] {
		lines = append(lines, fmt.Sprintf("%s = %s", k, val))
	}
	for k := range v.Secrets[service] {
		lines = append(lines, k)
	}
	sort.Strings(lines)
	return lines
}

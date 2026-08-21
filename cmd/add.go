package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/DomiIRL/vault-mcp/internal/vault"
	"github.com/spf13/cobra"
)

var addProperty bool

var addCmd = &cobra.Command{
	Use:   "add [--property] <zone/service> <KEY>",
	Short: "Add or update a secret (hidden input) or a property (visible input)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		service, key := args[0], args[1]

		var value string
		var err error
		if addProperty {
			fmt.Fprintf(os.Stderr, "Value for %s/%s (property, shown as you type): ", service, key)
			value, err = readVisible()
		} else {
			fmt.Fprintf(os.Stderr, "Value for %s/%s (input hidden): ", service, key)
			value, err = readSecret()
		}
		if err != nil {
			return err
		}

		vpass, err := ensureUnlocked()
		if err != nil {
			return err
		}

		v, err := vault.Load(vpass)
		if err != nil {
			return err
		}

		if v.Has(service, key) {
			fmt.Fprintf(os.Stderr, "Warning: %s/%s already exists. Overwrite? [y/N] ", service, key)
			var answer string
			fmt.Fscan(os.Stdin, &answer)
			if answer != "y" && answer != "Y" {
				fmt.Fprintln(os.Stderr, "Aborted.")
				return nil
			}
		}
		v.Set(service, key, value, addProperty)

		if err := vault.Save(vpass, v); err != nil {
			return fmt.Errorf("save vault: %w", err)
		}
		if err := vault.UpdateIndex(v); err != nil {
			return fmt.Errorf("update index: %w", err)
		}

		kind := "secret"
		if addProperty {
			kind = "property"
		}
		fmt.Fprintf(os.Stderr, "Saved %s/%s as %s.\n", service, key, kind)
		return nil
	},
}

func init() {
	addCmd.Flags().BoolVarP(&addProperty, "property", "p", false,
		"store as a non-secret property — value is echoed while typing and may be printed later")
}

// readVisible reads one line with the terminal's normal echo on, so a property
// value can be checked before it is stored.
func readVisible() (string, error) {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if err != nil && line == "" {
		return "", err
	}
	if line == "" {
		return "", errors.New("value cannot be empty")
	}
	return line, nil
}

func readSecret() (string, error) {
	b, err := readSecretBytes()
	if err != nil {
		return "", err
	}
	fmt.Fprintln(os.Stderr)
	// Strip UTF-8 BOM (PowerShell adds this when piping strings to native processes)
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		b = b[3:]
	}
	if len(b) == 0 {
		return "", errors.New("value cannot be empty")
	}
	return string(b), nil
}

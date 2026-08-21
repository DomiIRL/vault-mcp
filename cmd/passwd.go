package cmd

import (
	"fmt"
	"os"

	"github.com/DomiIRL/vault-mcp/internal/keychain"
	"github.com/DomiIRL/vault-mcp/internal/vault"
	"github.com/spf13/cobra"
)

var passwdCmd = &cobra.Command{
	Use:   "passwd",
	Short: "Change the vault master passphrase",
	Long: `Change the master passphrase used to encrypt the vault.

The vault is re-encrypted with the new passphrase and the keychain entry on
this machine is updated. Other machines will be prompted for the new passphrase
the next time they run any vault command.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		oldPass, err := ensureUnlocked()
		if err != nil {
			return err
		}

		s, err := vault.Load(oldPass)
		if err != nil {
			return fmt.Errorf("decrypt vault: %w", err)
		}

		fmt.Fprintln(os.Stderr, "Enter a new master passphrase.")
		newPass, err := promptPassphrase("New passphrase: ")
		if err != nil {
			return err
		}
		confirm, err := promptPassphrase("Confirm new passphrase: ")
		if err != nil {
			return err
		}
		if newPass != confirm {
			return fmt.Errorf("passphrases do not match")
		}
		if newPass == oldPass {
			return fmt.Errorf("new passphrase is the same as the current one")
		}

		if err := vault.Save(newPass, s); err != nil {
			return fmt.Errorf("re-encrypt vault: %w", err)
		}

		if err := keychain.StorePassphrase(newPass); err != nil {
			return fmt.Errorf("update keychain: %w", err)
		}

		fmt.Fprintln(os.Stderr, "Passphrase changed. Re-sync vault.age so other machines pick up the change.")
		fmt.Fprintln(os.Stderr, "Other machines will be prompted for the new passphrase on next use.")
		return nil
	},
}

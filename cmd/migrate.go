package cmd

import (
	"fmt"
	"os"
	"sort"

	"github.com/DomiIRL/vault-mcp/internal/vault"
	"github.com/spf13/cobra"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Reclassify address-shaped keys (hosts, ports, usernames) as properties",
	Long: `Scans the secret half of the vault for keys whose values are not credentials —
*_HOST, *_PORT, *_USER, *_URL, *_ENDPOINT, *_BUCKET, USERNAME, SERVER — and moves
them to properties, whose values may be printed.

Prints the plan and asks before writing. Anything it gets wrong is reversible with
'vault-mcp add <service> <KEY>' (secret) or 'vault-mcp add -p <service> <KEY>' (property).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		pass, err := ensureUnlocked()
		if err != nil {
			return err
		}
		v, err := vault.Load(pass)
		if err != nil {
			return err
		}

		type move struct{ service, key string }
		var moves []move
		for svc, keys := range v.Secrets {
			for k := range keys {
				if vault.LooksLikeProperty(k) {
					moves = append(moves, move{svc, k})
				}
			}
		}
		if len(moves) == 0 {
			fmt.Fprintln(os.Stderr, "Nothing to migrate — no address-shaped keys left in the secret half.")
			return nil
		}
		sort.Slice(moves, func(i, j int) bool {
			if moves[i].service != moves[j].service {
				return moves[i].service < moves[j].service
			}
			return moves[i].key < moves[j].key
		})

		fmt.Fprintf(os.Stderr, "Moving %d key(s) from secrets to properties:\n", len(moves))
		for _, m := range moves {
			fmt.Fprintf(os.Stderr, "  %s/%s\n", m.service, m.key)
		}
		fmt.Fprint(os.Stderr, "Proceed? [y/N] ")
		var answer string
		fmt.Fscan(os.Stdin, &answer)
		if answer != "y" && answer != "Y" {
			fmt.Fprintln(os.Stderr, "Aborted.")
			return nil
		}

		for _, m := range moves {
			v.Set(m.service, m.key, v.Secrets[m.service][m.key], true)
		}

		if err := vault.Save(pass, v); err != nil {
			return fmt.Errorf("save vault: %w", err)
		}
		if err := vault.UpdateIndex(v); err != nil {
			return fmt.Errorf("update index: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Migrated %d key(s). vault.age and index.md were rewritten.\n", len(moves))
		return nil
	},
}

package vault

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// UpdateIndex rewrites index.md to list all service/key names (no values).
func UpdateIndex(v *Vault) error {
	var sb strings.Builder
	sb.WriteString("# Vault Index\n\n")
	sb.WriteString("Key names stored in the vault. Values are never listed here.\n")
	sb.WriteString("Keys marked `(property)` hold non-secret values (hosts, ports, usernames) — ")
	sb.WriteString("`vault-mcp list` and the MCP `vault_list` print those values, secrets stay hidden.\n\n")

	for _, svc := range v.Services() {
		keys := make([]string, 0)
		for k := range v.Secrets[svc] {
			keys = append(keys, k)
		}
		for k := range v.Properties[svc] {
			keys = append(keys, k+" (property)")
		}
		sort.Strings(keys)
		sb.WriteString(fmt.Sprintf("## %s\n\n", svc))
		for _, k := range keys {
			name, suffix, _ := strings.Cut(k, " ")
			if suffix != "" {
				suffix = " " + suffix
			}
			sb.WriteString(fmt.Sprintf("- `%s`%s\n", name, suffix))
		}
		sb.WriteString("\n")
	}

	return os.WriteFile(IndexPath(), []byte(sb.String()), 0644)
}

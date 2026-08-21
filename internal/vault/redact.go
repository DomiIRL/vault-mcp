package vault

import (
	"sort"
	"strings"
	"sync"
)

// Keys whose values are addresses, ports or account names — never credentials.
// Used only to propose a classification (`vault-mcp migrate`); what is actually
// secret is decided by which half of the vault a key lives in.
var propertyKeys = map[string]bool{
	"SERVER": true, "USER": true, "USERNAME": true, "PORT": true, "HOST": true, "URL": true,
}

var propertySuffixes = []string{"_HOST", "_PORT", "_USER", "_USERNAME", "_URL", "_ENDPOINT", "_BUCKET"}

// Values shorter than this are too generic to search-and-replace without
// mangling unrelated output.
const minRedactLen = 6

var (
	mu         sync.RWMutex
	redactions []string
)

// TrackSecrets records the vault's secret half so Redact can strip it from
// anything handed back to the caller. Properties are left alone.
func TrackSecrets(v *Vault) {
	var vals []string
	seen := map[string]bool{}
	for _, val := range v.SecretValues() {
		if len(val) < minRedactLen || seen[val] {
			continue
		}
		seen[val] = true
		vals = append(vals, val)
	}
	// Longest first, so a value contained in another is not partially replaced.
	sort.Slice(vals, func(i, j int) bool { return len(vals[i]) > len(vals[j]) })

	mu.Lock()
	redactions = vals
	mu.Unlock()
}

// Redact blanks out every known secret found in text. It is the last line of
// defence for a command that echoes an injected credential back at us — once a
// value reaches the transcript it is leaked permanently.
func Redact(text string) string {
	mu.RLock()
	vals := redactions
	mu.RUnlock()

	for _, v := range vals {
		text = strings.ReplaceAll(text, v, "[REDACTED]")
	}
	return text
}

// LooksLikeProperty reports whether a key name is address-shaped rather than
// credential-shaped.
func LooksLikeProperty(key string) bool {
	k := strings.ToUpper(key)
	if propertyKeys[k] {
		return true
	}
	for _, suffix := range propertySuffixes {
		if strings.HasSuffix(k, suffix) {
			return true
		}
	}
	return false
}

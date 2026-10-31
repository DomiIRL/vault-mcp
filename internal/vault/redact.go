package vault

import (
	"encoding/base64"
	"sort"
	"strings"
	"sync"
	"unicode"
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
	add := func(val string) {
		if len(val) < minRedactLen || seen[val] {
			return
		}
		seen[val] = true
		vals = append(vals, val)
	}
	for _, keys := range v.Secrets {
		for key, val := range keys {
			add(val)
			if strings.HasSuffix(key, FileSuffix) {
				fileTokens(val, add)
			}
		}
	}
	// Longest first, so a value contained in another is not partially replaced.
	sort.Slice(vals, func(i, j int) bool { return len(vals[i]) > len(vals[j]) })

	mu.Lock()
	redactions = vals
	mu.Unlock()
}

// Commands print a file secret's pieces, not its base64 whole: a kubeconfig's
// client-key-data comes back on its own from `kubectl config view --raw`, and
// piped through `base64 -d` it becomes PEM lines. Long tokens are the
// credentials; labels and URLs stay readable.
const minFileTokenLen = 32

func fileTokens(b64 string, add func(string)) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return
	}
	add(strings.TrimSpace(string(data)))
	for _, tok := range strings.FieldsFunc(string(data), isTokenSeparator) {
		if len(tok) < minFileTokenLen || strings.Contains(tok, "://") {
			continue
		}
		add(tok)
		if inner, err := base64.StdEncoding.DecodeString(tok); err == nil && strings.Contains(string(inner), "-----BEGIN") {
			for _, line := range strings.Fields(string(inner)) {
				if len(line) >= minFileTokenLen {
					add(line)
				}
			}
		}
	}
}

// JSON kubeconfigs have no whitespace, so quotes and brackets split tokens too.
func isTokenSeparator(r rune) bool {
	return unicode.IsSpace(r) || strings.ContainsRune(`"',{}[]`, r)
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

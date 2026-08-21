package vault

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// Secrets is the in-memory representation: service -> key -> value.
type Secrets map[string]map[string]string

// Vault splits stored values in two: Secrets must never reach a transcript,
// Properties (hosts, ports, usernames, endpoints) are safe to print. Both are
// injected as env vars identically — the split is only about disclosure.
type Vault struct {
	Secrets    Secrets `json:"secrets"`
	Properties Secrets `json:"properties"`
}

func (v *Vault) Services() []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range []Secrets{v.Secrets, v.Properties} {
		for svc := range m {
			if !seen[svc] {
				seen[svc] = true
				out = append(out, svc)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ServiceEnv returns the merged key->value map for one service.
func (v *Vault) ServiceEnv(service string) (map[string]string, error) {
	env := map[string]string{}
	for _, m := range []Secrets{v.Properties, v.Secrets} {
		for k, val := range m[service] {
			env[k] = val
		}
	}
	if len(env) == 0 {
		return nil, fmt.Errorf("service %q not found in vault", service)
	}
	return env, nil
}

// Set stores key under the chosen half, removing it from the other one so a key
// can be reclassified in place.
func (v *Vault) Set(service, key, value string, property bool) {
	v.Delete(service, key)
	target := &v.Secrets
	if property {
		target = &v.Properties
	}
	if *target == nil {
		*target = Secrets{}
	}
	if (*target)[service] == nil {
		(*target)[service] = map[string]string{}
	}
	(*target)[service][key] = value
}

// Delete removes key from whichever half holds it. Reports whether it existed.
func (v *Vault) Delete(service, key string) bool {
	found := false
	for _, m := range []Secrets{v.Secrets, v.Properties} {
		if _, ok := m[service][key]; ok {
			delete(m[service], key)
			found = true
		}
		if len(m[service]) == 0 {
			delete(m, service)
		}
	}
	return found
}

func (v *Vault) Has(service, key string) bool {
	_, s := v.Secrets[service][key]
	_, p := v.Properties[service][key]
	return s || p
}

// SecretValues returns every value that must be kept out of output.
func (v *Vault) SecretValues() []string {
	var out []string
	for _, keys := range v.Secrets {
		for _, val := range keys {
			out = append(out, val)
		}
	}
	return out
}

func root() string {
	if r := os.Getenv("VAULT_ROOT"); r != "" {
		return r
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".vault")
}

func VaultPath() string     { return filepath.Join(root(), "vault.age") }
func DecryptedPath() string { return filepath.Join(root(), "decrypted") }
func IndexPath() string     { return filepath.Join(root(), "index.md") }

// Init creates an empty encrypted vault at VaultPath.
func Init(passphrase string) error {
	if err := os.MkdirAll(filepath.Dir(VaultPath()), 0700); err != nil {
		return err
	}
	return save(passphrase, &Vault{Secrets: Secrets{}, Properties: Secrets{}})
}

// Load decrypts and returns the vault contents.
func Load(passphrase string) (*Vault, error) {
	f, err := os.Open(VaultPath())
	if err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}
	defer f.Close()

	id, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, fmt.Errorf("create identity: %w", err)
	}

	src := armorOrBinary(f)
	r, err := age.Decrypt(src, id)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w (wrong passphrase?)", err)
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read vault: %w", err)
	}

	var v Vault
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("parse vault: %w", err)
	}
	// Pre-properties vaults are a bare service->key->value map, which decodes
	// into an empty Vault. Read it again as all-secret.
	if v.Secrets == nil && v.Properties == nil {
		var legacy Secrets
		if err := json.Unmarshal(data, &legacy); err != nil {
			return nil, fmt.Errorf("parse vault: %w", err)
		}
		v.Secrets = legacy
	}
	if v.Secrets == nil {
		v.Secrets = Secrets{}
	}
	if v.Properties == nil {
		v.Properties = Secrets{}
	}
	return &v, nil
}

// Save re-encrypts and writes the vault.
func Save(passphrase string, v *Vault) error {
	return save(passphrase, v)
}

func save(passphrase string, v *Vault) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	return os.WriteFile(VaultPath(), buf.Bytes(), 0600)
}

// armorOrBinary peeks at the first bytes of r and wraps it in armor.NewReader
// if it starts with the PEM header, otherwise returns it unchanged.
func armorOrBinary(r io.Reader) io.Reader {
	br := bufio.NewReader(r)
	peek, _ := br.Peek(len(armor.Header))
	if string(peek) == armor.Header {
		return armor.NewReader(br)
	}
	return br
}

// WriteDecrypted writes .env and .ps1 files for every service to DecryptedPath.
func (v *Vault) WriteDecrypted() error {
	dir := DecryptedPath()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for _, service := range v.Services() {
		keys, err := v.ServiceEnv(service)
		if err != nil {
			return err
		}
		if err := writeServiceFiles(dir, service, keys); err != nil {
			return err
		}
	}
	return nil
}

// RemoveDecrypted securely deletes the decrypted directory.
func RemoveDecrypted() error {
	dir := DecryptedPath()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	// Overwrite each file before removal.
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		zeros := make([]byte, info.Size())
		_ = os.WriteFile(path, zeros, 0600)
		_ = os.Remove(path)
	}
	return os.Remove(dir)
}

func writeServiceFiles(dir, service string, keys map[string]string) error {
	filename := strings.ReplaceAll(service, "/", "-")

	var env, ps1 strings.Builder
	for k, v := range keys {
		env.WriteString(k + "=" + v + "\n")
		ps1.WriteString(`$env:` + k + ` = "` + strings.ReplaceAll(v, `"`, "`\"") + `"` + "\n")
	}

	if err := os.WriteFile(filepath.Join(dir, filename+".env"), []byte(env.String()), 0600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, filename+".ps1"), []byte(ps1.String()), 0600)
}

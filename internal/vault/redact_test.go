package vault

import (
	"encoding/json"
	"testing"
)

func testVault() *Vault {
	v := &Vault{Secrets: Secrets{}, Properties: Secrets{}}
	v.Set("homeserver/db", "SSH_HOST", "db.example.com", true)
	v.Set("homeserver/db", "SSH_USER", "root", true)
	v.Set("homeserver/db", "SSH_PASSWORD", "hunter2-correct-horse", false)
	v.Set("cloudflare", "API_TOKEN", "tok_abcdef123456", false)
	v.Set("tiny", "PIN", "1234", false)
	return v
}

func TestRedact(t *testing.T) {
	TrackSecrets(testVault())

	cases := []struct{ in, want string }{
		{"export SSH_PASSWORD='hunter2-correct-horse'", "export SSH_PASSWORD='[REDACTED]'"},
		{"curl -H 'Bearer tok_abcdef123456'", "curl -H 'Bearer [REDACTED]'"},
		{"ssh root@db.example.com", "ssh root@db.example.com"},
		{"exit code 1234", "exit code 1234"},
	}
	for _, c := range cases {
		if got := Redact(c.in); got != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSetReclassifies(t *testing.T) {
	v := testVault()
	v.Set("cloudflare", "API_TOKEN", "tok_abcdef123456", true)

	if _, still := v.Secrets["cloudflare"]["API_TOKEN"]; still {
		t.Error("reclassified key still in the secret half")
	}
	TrackSecrets(v)
	if got := Redact("tok_abcdef123456"); got != "tok_abcdef123456" {
		t.Errorf("property value was redacted: %q", got)
	}
}

func TestServiceEnvMerges(t *testing.T) {
	env, err := testVault().ServiceEnv("homeserver/db")
	if err != nil {
		t.Fatal(err)
	}
	if env["SSH_HOST"] != "db.example.com" || env["SSH_PASSWORD"] != "hunter2-correct-horse" {
		t.Errorf("ServiceEnv did not merge both halves: %v", env)
	}
	if _, err := testVault().ServiceEnv("nope"); err == nil {
		t.Error("expected an error for an unknown service")
	}
}

func TestDelete(t *testing.T) {
	v := testVault()
	if !v.Delete("homeserver/db", "SSH_HOST") || v.Has("homeserver/db", "SSH_HOST") {
		t.Error("Delete did not remove a property")
	}
	if v.Delete("homeserver/db", "MISSING") {
		t.Error("Delete reported success for a missing key")
	}
	if !v.Delete("tiny", "PIN") {
		t.Fatal("Delete failed on the last key of a service")
	}
	if _, ok := v.Secrets["tiny"]; ok {
		t.Error("emptied service was not dropped")
	}
}

// A pre-properties vault is a bare service->key->value map and must load as all-secret.
func TestLegacyFormatDecodesAsSecrets(t *testing.T) {
	var v Vault
	legacyJSON := []byte(`{"cloudflare":{"API_TOKEN":"tok_abcdef123456"}}`)
	if err := json.Unmarshal(legacyJSON, &v); err != nil {
		t.Fatal(err)
	}
	if v.Secrets != nil || v.Properties != nil {
		t.Fatal("legacy JSON must not populate the v2 fields — Load's fallback depends on this")
	}
}

func TestLooksLikeProperty(t *testing.T) {
	for _, k := range []string{"SSH_HOST", "SSH_PORT", "SSH_USER", "USERNAME", "S3_ENDPOINT", "HA_URL", "SERVER"} {
		if !LooksLikeProperty(k) {
			t.Errorf("%s should be classified as a property", k)
		}
	}
	for _, k := range []string{"SSH_PASSWORD", "API_TOKEN", "S3_ACCESS_KEY_ID", "CLIENT_SECRET", "MONGO_ROOT_PASSWORD"} {
		if LooksLikeProperty(k) {
			t.Errorf("%s must stay a secret", k)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("VAULT_ROOT", t.TempDir())
	if err := Init("pw"); err != nil {
		t.Fatal(err)
	}
	if err := Save("pw", testVault()); err != nil {
		t.Fatal(err)
	}
	v, err := Load("pw")
	if err != nil {
		t.Fatal(err)
	}
	if v.Properties["homeserver/db"]["SSH_HOST"] != "db.example.com" ||
		v.Secrets["homeserver/db"]["SSH_PASSWORD"] != "hunter2-correct-horse" {
		t.Errorf("round trip lost the split: %+v", v)
	}
	if err := UpdateIndex(v); err != nil {
		t.Fatal(err)
	}
}

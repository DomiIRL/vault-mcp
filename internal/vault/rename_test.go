package vault

import "testing"

func TestRenamePrefixMovesSecretsAndProperties(t *testing.T) {
	v := &Vault{Secrets: Secrets{}, Properties: Secrets{}}
	v.Set("work/onedev", "API_TOKEN", "t", false)
	v.Set("work/onedev", "HOST", "h", true)
	v.Set("work/kanban", "API_KEY", "k", false)
	v.Set("work-old/other", "X", "x", false)

	moves, err := v.Rename("work/", "acme/")
	if err != nil {
		t.Fatal(err)
	}
	if len(moves) != 2 {
		t.Fatalf("moved %v, want the two work/ services", moves)
	}
	if !v.Has("acme/onedev", "API_TOKEN") || !v.Has("acme/onedev", "HOST") || !v.Has("acme/kanban", "API_KEY") {
		t.Fatal("renamed keys missing")
	}
	if v.Properties["acme/onedev"]["HOST"] != "h" {
		t.Fatal("property did not stay a property")
	}
	if v.Has("work/onedev", "API_TOKEN") || !v.Has("work-old/other", "X") {
		t.Fatal("prefix matched wrong services")
	}
}

func TestRenameRefusesTakenName(t *testing.T) {
	v := &Vault{Secrets: Secrets{}, Properties: Secrets{}}
	v.Set("a/x", "K", "1", false)
	v.Set("b/x", "K", "2", false)
	if _, err := v.Rename("a/", "b/"); err == nil {
		t.Fatal("expected an error")
	}
	if v.Secrets["a/x"]["K"] != "1" || v.Secrets["b/x"]["K"] != "2" {
		t.Fatal("vault changed on a refused rename")
	}
}

package vault

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunExecMaterialisesFileSecret(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	content := "apiVersion: v1\nkind: Config\n"
	env := map[string]string{"KUBECONFIG" + FileSuffix: base64.StdEncoding.EncodeToString([]byte(content))}

	var out bytes.Buffer
	err := RunExec(env, []string{"sh", "-c", `printf '%s\n' "$KUBECONFIG"; stat -c %a "$KUBECONFIG"; cat "$KUBECONFIG"; printf '%s' "${KUBECONFIG_FILE_B64-unset}"`},
		&out, os.Stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitN(out.String(), "\n", 3)
	path, mode, rest := lines[0], lines[1], lines[2]
	if filepath.Dir(path) != dir {
		t.Errorf("temp file %s is outside XDG_RUNTIME_DIR %s", path, dir)
	}
	if mode != "600" {
		t.Errorf("temp file mode = %s, want 600", mode)
	}
	if rest != content+"unset" {
		t.Errorf("file content / raw key = %q", rest)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("temp file %s still exists after the command", path)
	}
}

func TestRunExecCleansUpWhenALaterFileFails(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	env := map[string]string{
		"GOOD" + FileSuffix: base64.StdEncoding.EncodeToString([]byte("x")),
		"BAD" + FileSuffix:  "not base64!",
	}
	// Map order is random, so run enough times to hit the good-then-bad order.
	for i := 0; i < 20; i++ {
		if err := RunExec(env, []string{"true"}, os.Stdout, os.Stderr, nil); err == nil {
			t.Fatal("expected an error for an undecodable file secret")
		}
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Errorf("%d temp files left behind", len(left))
	}
}

func TestSSHPreambleSkipsFileSecrets(t *testing.T) {
	got := shellExportPreamble(map[string]string{"KUBECONFIG" + FileSuffix: "abc", "TOKEN": "t"})
	if strings.Contains(got, "KUBECONFIG") || !strings.Contains(got, "TOKEN") {
		t.Errorf("preamble = %q", got)
	}
}

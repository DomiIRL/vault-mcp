package vault

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

// FileSuffix marks a key whose value is a whole file, base64-encoded. RunExec
// writes it to a private temp file and sets the name without the suffix to its
// path, so KUBECONFIG_FILE_B64 arrives as KUBECONFIG=<runtime dir>/vault-....
const FileSuffix = "_FILE_B64"

// RunExec runs cmdArgs as a subprocess with env secrets overlaid on the current environment.
func RunExec(env map[string]string, cmdArgs []string, stdout, stderr io.Writer, stdin io.Reader) error {
	c := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	c.Stdout = stdout
	c.Stderr = stderr
	c.Stdin = stdin
	c.Env = os.Environ()
	for k, v := range env {
		if name, ok := strings.CutSuffix(k, FileSuffix); ok {
			path, err := writeTempFile(v)
			if err != nil {
				return fmt.Errorf("materialise %s: %w", k, err)
			}
			defer os.Remove(path)
			c.Env = append(c.Env, name+"="+path)
			continue
		}
		c.Env = append(c.Env, k+"="+v)
	}

	// An interrupt would kill this process before the deferred removes run and
	// leave a credential file behind, so it goes to the child instead.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	if err := c.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case s := <-sigs:
				c.Process.Signal(s)
			case <-done:
				return
			}
		}
	}()
	return c.Wait()
}

func writeTempFile(b64 string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	// XDG_RUNTIME_DIR is a per-user tmpfs, so a file a SIGKILL strands never
	// reaches disk and is gone at logout. CreateTemp opens with 0600.
	f, err := os.CreateTemp(os.Getenv("XDG_RUNTIME_DIR"), "vault-*")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), f.Close()
}

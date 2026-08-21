package vault

import (
	"io"
	"os"
	"os/exec"
)

// RunExec runs cmdArgs as a subprocess with env secrets overlaid on the current environment.
func RunExec(env map[string]string, cmdArgs []string, stdout, stderr io.Writer, stdin io.Reader) error {
	c := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	c.Stdout = stdout
	c.Stderr = stderr
	c.Stdin = stdin
	c.Env = os.Environ()
	for k, v := range env {
		c.Env = append(c.Env, k+"="+v)
	}
	return c.Run()
}

package vault

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// DialSSH opens an authenticated SSH connection using credentials from env.
func DialSSH(env map[string]string) (*ssh.Client, error) {
	host, user, password, port, err := sshParams(env)
	if err != nil {
		return nil, err
	}

	cb, err := hostKeyCallback()
	if err != nil {
		return nil, err
	}

	return ssh.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)), &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: cb,
	})
}

// RunSSH connects to the host defined in env and runs command.
func RunSSH(env map[string]string, command string, stdout, stderr io.Writer) error {
	client, err := DialSSH(env)
	if err != nil {
		return fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()
	return runSession(client, command, nil, stdout, stderr)
}

// RunSSHWithStdin runs command on the remote host, feeding stdin as the
// command's standard input. Useful when stdin content contains shell-special
// characters that would break inline echo-pipe embedding.
func RunSSHWithStdin(env map[string]string, command, stdinContent string, stdout, stderr io.Writer) error {
	client, err := DialSSH(env)
	if err != nil {
		return fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()
	return runSession(client, command, strings.NewReader(stdinContent), stdout, stderr)
}

// PutFile uploads content to remotePath on the host defined in env via SFTP.
func PutFile(env map[string]string, remotePath string, content []byte, mode os.FileMode) error {
	client, err := DialSSH(env)
	if err != nil {
		return fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()

	sc, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("sftp open: %w", err)
	}
	defer sc.Close()

	f, err := sc.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("sftp create %s: %w", remotePath, err)
	}
	if _, err = f.Write(content); err != nil {
		_ = f.Close()
		return fmt.Errorf("sftp write: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("sftp close: %w", err)
	}
	return sc.Chmod(remotePath, mode)
}

// GetFile downloads remotePath from the host defined in env via SFTP.
func GetFile(env map[string]string, remotePath string) ([]byte, error) {
	client, err := DialSSH(env)
	if err != nil {
		return nil, fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()

	sc, err := sftp.NewClient(client)
	if err != nil {
		return nil, fmt.Errorf("sftp open: %w", err)
	}
	defer sc.Close()

	f, err := sc.Open(remotePath)
	if err != nil {
		return nil, fmt.Errorf("sftp open %s: %w", remotePath, err)
	}
	defer f.Close()

	return io.ReadAll(f)
}

func runSession(client *ssh.Client, command string, stdin io.Reader, stdout, stderr io.Writer) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	session.Stdout = stdout
	session.Stderr = stderr
	if stdin != nil {
		session.Stdin = stdin
	}
	return session.Run(command)
}

func sshParams(env map[string]string) (host, user, password string, port int, err error) {
	host = env["SSH_HOST"]
	password = env["SSH_PASSWORD"]
	if host == "" || password == "" {
		return "", "", "", 0, fmt.Errorf("service must have SSH_HOST and SSH_PASSWORD")
	}
	user = env["SSH_USER"]
	if user == "" {
		user = "root"
	}
	port = 22
	if p, e := strconv.Atoi(env["SSH_PORT"]); e == nil && p > 0 {
		port = p
	}
	return
}

func hostKeyCallback() (ssh.HostKeyCallback, error) {
	home, _ := os.UserHomeDir()
	knownHostsPath := filepath.Join(home, ".ssh", "known_hosts")
	sshDir := filepath.Join(home, ".ssh")

	appendKey := func(hostname string, key ssh.PublicKey) error {
		_ = os.MkdirAll(sshDir, 0700)
		f, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = fmt.Fprintln(f, knownhosts.Line([]string{hostname}, key))
		if err == nil {
			fmt.Fprintf(os.Stderr, "vault: added %s to known_hosts (TOFU)\n", hostname)
		}
		return err
	}

	if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
		return func(hostname string, _ net.Addr, key ssh.PublicKey) error {
			return appendKey(hostname, key)
		}, nil
	}

	// File exists: validate known hosts; TOFU for hosts not yet in the file.
	cb, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("parse known_hosts: %w", err)
	}
	return func(hostname string, addr net.Addr, key ssh.PublicKey) error {
		err := cb(hostname, addr, key)
		if err == nil {
			return nil
		}
		var kerr *knownhosts.KeyError
		if errors.As(err, &kerr) && len(kerr.Want) == 0 {
			// Host not in file — TOFU.
			return appendKey(hostname, key)
		}
		return err
	}, nil
}

// RunSSHWithEnv connects via SSH using sshEnv credentials and runs command
// with key/value pairs from extraEnv injected as shell exports. Secret values
// are only handled inside this process — they never appear in tool parameters
// or results visible to Claude.
func RunSSHWithEnv(sshEnv, extraEnv map[string]string, command string, stdout, stderr io.Writer) error {
	client, err := DialSSH(sshEnv)
	if err != nil {
		return fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()
	return runSession(client, shellExportPreamble(extraEnv)+command, nil, stdout, stderr)
}

// shellExportPreamble builds "export K1='v1'; export K2='v2'; " for a remote shell.
// File secrets are left out: they only materialise locally, and the whole file
// would otherwise sit on the remote command line.
func shellExportPreamble(env map[string]string) string {
	var b strings.Builder
	for k, v := range env {
		if strings.HasSuffix(k, FileSuffix) {
			continue
		}
		b.WriteString("export ")
		b.WriteString(k)
		b.WriteString("='")
		b.WriteString(strings.ReplaceAll(v, "'", `'\''`))
		b.WriteString("'; ")
	}
	return b.String()
}

// ShellJoin builds a single shell command string from args, quoting as needed.
func ShellJoin(args []string) string {
	if len(args) == 0 {
		return ""
	}
	result := shellQuote(args[0])
	for _, a := range args[1:] {
		result += " " + shellQuote(a)
	}
	return result
}

func shellQuote(s string) string {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '/' || c == ':' || c == '=') {
			return "'" + s + "'"
		}
	}
	return s
}

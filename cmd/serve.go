package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/DomiIRL/vault-mcp/internal/keychain"
	"github.com/DomiIRL/vault-mcp/internal/vault"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server on stdio (for Claude Code and other MCP clients)",
	RunE: func(cmd *cobra.Command, args []string) error {
		s := server.NewMCPServer("vault", "1.0.0",
			server.WithToolCapabilities(false),
		)

		s.AddTool(mcp.NewTool("vault_ssh",
			mcp.WithDescription("Run a shell command on a remote host via SSH. The command string is passed directly to the remote shell, so pipes, redirects, and multi-word arguments all work. Credentials are injected from the vault — never exposed."),
			mcp.WithString("service", mcp.Required(), mcp.Description("Vault service path, e.g. homeserver/db")),
			mcp.WithString("command", mcp.Required(), mcp.Description("Remote shell command to execute (passed as-is to the remote shell)")),
		), handleSSH)

		s.AddTool(mcp.NewTool("vault_ssh_with_stdin",
			mcp.WithDescription("Run a remote shell command via SSH with explicit stdin content. Use when the remote command reads from stdin and the content contains characters that would break inline echo-pipe embedding (newlines, quotes, backslashes)."),
			mcp.WithString("service", mcp.Required(), mcp.Description("Vault service path, e.g. homeserver/db")),
			mcp.WithString("command", mcp.Required(), mcp.Description("Remote shell command to execute")),
			mcp.WithString("stdin", mcp.Required(), mcp.Description("Content to feed to the command's stdin")),
		), handleSSHWithStdin)

		s.AddTool(mcp.NewTool("vault_ssh_put",
			mcp.WithDescription("Upload a file to a remote host via SFTP. Provide either 'content' (inline text) or 'local_path' (absolute path on this machine) — not both. 'remote_path' must be an absolute path on the remote host. 'mode' is an octal permission string (default 0644)."),
			mcp.WithString("service", mcp.Required(), mcp.Description("Vault service path, e.g. homeserver/db")),
			mcp.WithString("remote_path", mcp.Required(), mcp.Description("Absolute path on the remote host to write")),
			mcp.WithString("content", mcp.Description("Inline text content to write")),
			mcp.WithString("local_path", mcp.Description("Absolute local file path to upload")),
			mcp.WithString("mode", mcp.Description("Octal permission mode, default 0644")),
		), handleSSHPut)

		s.AddTool(mcp.NewTool("vault_ssh_get",
			mcp.WithDescription("Read a file from a remote host via SFTP and return its content as text. Useful for reading config files, logs, or script output without needing 'cat' over SSH."),
			mcp.WithString("service", mcp.Required(), mcp.Description("Vault service path, e.g. homeserver/db")),
			mcp.WithString("remote_path", mcp.Required(), mcp.Description("Absolute path on the remote host to read")),
		), handleSSHGet)

		s.AddTool(mcp.NewTool("vault_ssh_exec",
			mcp.WithDescription("SSH into a host using one service's credentials and run a command with a second service's secrets injected as environment variables. Use when an API or tool is only reachable from a specific remote host (e.g. an internal service accessible only from sol)."),
			mcp.WithString("ssh_service", mcp.Required(), mcp.Description("Vault service path providing SSH credentials, e.g. homeserver/bastion")),
			mcp.WithString("env_service", mcp.Required(), mcp.Description("Vault service path whose keys are injected as env vars on the remote host, e.g. homeserver/gitea")),
			mcp.WithString("command", mcp.Required(), mcp.Description("Remote shell command to execute (may reference the injected env vars by name)")),
		), handleSSHExec)

		s.AddTool(mcp.NewTool("vault_exec",
			mcp.WithDescription("Run a local command with a service's secrets injected as environment variables. Credential values are never visible to Claude."),
			mcp.WithString("service", mcp.Required(), mcp.Description("Vault service path, e.g. homeserver/cloudflare")),
			mcp.WithString("command", mcp.Required(), mcp.Description("Executable to run")),
			mcp.WithArray("args", mcp.Description("Arguments for the command")),
		), handleExec)

		s.AddTool(mcp.NewTool("vault_list",
			mcp.WithDescription("List all services and key names stored in the vault. Property values (hosts, ports, usernames, endpoints) are returned; secret values never are."),
		), handleList)

		return server.ServeStdio(s)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

// loadVault reads the passphrase from the keychain and decrypts the vault.
// Never prompts — returns a clear error if the machine is not registered.
func loadVault() (*vault.Vault, error) {
	pass, err := keychain.LoadPassphrase()
	if err != nil {
		return nil, fmt.Errorf("vault not registered on this machine — run 'vault-mcp init' in a terminal first")
	}
	v, err := vault.Load(pass)
	if err != nil {
		return nil, err
	}
	vault.TrackSecrets(v)
	return v, nil
}

// Every tool result goes through toolError/toolText, so redacting here covers
// command output, file reads and error strings alike.
func toolError(msg string) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.TextContent{Type: "text", Text: vault.Redact(msg)}},
		IsError: true,
	}, nil
}

func toolText(text string) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultText(vault.Redact(text)), nil
}

func handleSSH(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, _ := req.Params.Arguments.(map[string]any)
	service, _ := args["service"].(string)
	command, _ := args["command"].(string)
	if service == "" || command == "" {
		return toolError("service and command are required")
	}

	s, err := loadVault()
	if err != nil {
		return toolError(err.Error())
	}
	env, err := s.ServiceEnv(service)
	if err != nil {
		return toolError(err.Error())
	}

	var stdout, stderr bytes.Buffer
	runErr := vault.RunSSH(env, command, &stdout, &stderr)
	return sshResult(stdout, stderr, runErr)
}

func handleSSHWithStdin(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, _ := req.Params.Arguments.(map[string]any)
	service, _ := args["service"].(string)
	command, _ := args["command"].(string)
	stdin, _ := args["stdin"].(string)
	if service == "" || command == "" {
		return toolError("service and command are required")
	}

	s, err := loadVault()
	if err != nil {
		return toolError(err.Error())
	}
	env, err := s.ServiceEnv(service)
	if err != nil {
		return toolError(err.Error())
	}

	var stdout, stderr bytes.Buffer
	runErr := vault.RunSSHWithStdin(env, command, stdin, &stdout, &stderr)
	return sshResult(stdout, stderr, runErr)
}

func handleSSHPut(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, _ := req.Params.Arguments.(map[string]any)
	service, _ := args["service"].(string)
	remotePath, _ := args["remote_path"].(string)
	content, _ := args["content"].(string)
	localPath, _ := args["local_path"].(string)
	modeStr, _ := args["mode"].(string)

	if service == "" || remotePath == "" {
		return toolError("service and remote_path are required")
	}
	if content == "" && localPath == "" {
		return toolError("one of content or local_path is required")
	}
	if content != "" && localPath != "" {
		return toolError("provide content or local_path, not both")
	}

	var data []byte
	if localPath != "" {
		var err error
		data, err = os.ReadFile(localPath)
		if err != nil {
			return toolError(fmt.Sprintf("read local_path: %v", err))
		}
	} else {
		data = []byte(content)
	}

	mode := os.FileMode(0644)
	if modeStr != "" {
		n, err := strconv.ParseUint(modeStr, 8, 32)
		if err != nil {
			return toolError(fmt.Sprintf("invalid mode %q: %v", modeStr, err))
		}
		mode = os.FileMode(n)
	}

	s, err := loadVault()
	if err != nil {
		return toolError(err.Error())
	}
	env, err := s.ServiceEnv(service)
	if err != nil {
		return toolError(err.Error())
	}

	if err := vault.PutFile(env, remotePath, data, mode); err != nil {
		return toolError(err.Error())
	}
	return toolText(fmt.Sprintf("uploaded %d bytes to %s", len(data), remotePath))
}

func handleSSHGet(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, _ := req.Params.Arguments.(map[string]any)
	service, _ := args["service"].(string)
	remotePath, _ := args["remote_path"].(string)
	if service == "" || remotePath == "" {
		return toolError("service and remote_path are required")
	}

	s, err := loadVault()
	if err != nil {
		return toolError(err.Error())
	}
	env, err := s.ServiceEnv(service)
	if err != nil {
		return toolError(err.Error())
	}

	data, err := vault.GetFile(env, remotePath)
	if err != nil {
		return toolError(err.Error())
	}
	return toolText(string(data))
}

func handleSSHExec(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, _ := req.Params.Arguments.(map[string]any)
	sshService, _ := args["ssh_service"].(string)
	envService, _ := args["env_service"].(string)
	command, _ := args["command"].(string)
	if sshService == "" || envService == "" || command == "" {
		return toolError("ssh_service, env_service, and command are required")
	}

	s, err := loadVault()
	if err != nil {
		return toolError(err.Error())
	}
	sshEnv, err := s.ServiceEnv(sshService)
	if err != nil {
		return toolError(err.Error())
	}
	extraEnv, err := s.ServiceEnv(envService)
	if err != nil {
		return toolError(err.Error())
	}

	var stdout, stderr bytes.Buffer
	runErr := vault.RunSSHWithEnv(sshEnv, extraEnv, command, &stdout, &stderr)
	return sshResult(stdout, stderr, runErr)
}

func handleExec(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, _ := req.Params.Arguments.(map[string]any)
	service, _ := args["service"].(string)
	command, _ := args["command"].(string)
	if service == "" || command == "" {
		return toolError("service and command are required")
	}

	var cmdArgs []string
	if rawArgs, ok := args["args"].([]interface{}); ok {
		for _, a := range rawArgs {
			if s, ok := a.(string); ok {
				cmdArgs = append(cmdArgs, s)
			}
		}
	}

	s, err := loadVault()
	if err != nil {
		return toolError(err.Error())
	}
	env, err := s.ServiceEnv(service)
	if err != nil {
		return toolError(err.Error())
	}

	var stdout, stderr bytes.Buffer
	runErr := vault.RunExec(env, append([]string{command}, cmdArgs...), &stdout, &stderr, nil)

	var out strings.Builder
	out.WriteString(stdout.String())
	if stderr.Len() > 0 {
		if out.Len() > 0 {
			out.WriteString("\n")
		}
		out.WriteString("[stderr]\n" + stderr.String())
	}
	if runErr != nil {
		return toolError(out.String() + "\n[error] " + runErr.Error())
	}
	return toolText(out.String())
}

func handleList(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s, err := loadVault()
	if err != nil {
		return toolError(err.Error())
	}

	var out strings.Builder
	out.WriteString("Services in vault (properties show their value, secrets do not):\n\n")
	for _, service := range s.Services() {
		out.WriteString("  " + service + "\n")
		for _, line := range serviceLines(s, service) {
			out.WriteString("    - " + line + "\n")
		}
	}
	return toolText(out.String())
}

// sshResult formats combined stdout/stderr + error into a tool result.
func sshResult(stdout, stderr bytes.Buffer, runErr error) (*mcp.CallToolResult, error) {
	var out strings.Builder
	if stdout.Len() > 0 {
		out.WriteString(stdout.String())
	}
	if stderr.Len() > 0 {
		if out.Len() > 0 {
			out.WriteString("\n")
		}
		out.WriteString("[stderr]\n")
		out.WriteString(stderr.String())
	}
	if runErr != nil {
		if out.Len() > 0 {
			out.WriteString("\n")
		}
		out.WriteString("[error] " + runErr.Error())
		return toolError(out.String())
	}
	return toolText(out.String())
}

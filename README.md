# vault-mcp

An encrypted secrets vault with an MCP server, so an AI coding agent can *use* your
credentials without ever *seeing* them.

Everything lives in one `age`-encrypted file. The master passphrase sits in your OS
keychain, never in the file, never in git. The agent gets `ssh` and `exec` proxy tools:
it says "run this command on that host", the binary injects the credentials, and every
secret value is stripped out of the output before the agent reads it.

## Why

The usual options are bad. A `.env` the agent can `cat` is a secret in the transcript.
Pasting a token into chat is a secret in the transcript forever. A hosted secrets
manager is an account, a bill, and a network dependency for something that is one file
on your disk.

## Install

```bash
go install github.com/DomiIRL/vault-mcp@latest
```

Binary lands in `$(go env GOPATH)/bin` — make sure that is on your `PATH`.

## Quickstart

```bash
vault-mcp add homeserver/db DB_PASSWORD     # prompts, input hidden
vault-mcp add -p homeserver/db DB_HOST      # a property: input visible, printable later
vault-mcp list                              # key names, plus property values
```

The first command walks you through creating the vault and picking a master passphrase.
Files land in `~/.vault/` (`VAULT_ROOT` overrides the directory):

```
~/.vault/
├── vault.age     # the encrypted vault — safe to commit or sync
├── index.md      # key names only, no values — generated
└── decrypted/    # only exists between `unlock` and `lock`
```

`vault.age` is safe to put in a private *or* public git repo — it is scrypt-encrypted
and useless without the passphrase. That is the intended way to sync it between
machines: clone the repo on machine two, run any `vault-mcp` command, enter the same
passphrase once, done.

## Wire it into Claude Code

```bash
claude mcp add --scope user vault -- "$(go env GOPATH)/bin/vault-mcp" serve
```

`--scope user` registers it globally, so the vault is available in every project rather
than one repo. Restart Claude Code and the tools show up.

Other MCP clients: the server speaks MCP over stdio, so the command is
`vault-mcp serve` with no arguments.

### Tools the agent gets

| Tool | What it does |
|---|---|
| `vault_list()` | Services and key names. Property values shown, secret values never |
| `vault_ssh(service, command)` | Run a command on a remote host |
| `vault_ssh_with_stdin(service, command, stdin)` | Same, with explicit stdin |
| `vault_ssh_put(service, remote_path, content \| local_path)` | Upload a file over SFTP |
| `vault_ssh_get(service, remote_path)` | Read a remote file over SFTP |
| `vault_ssh_exec(ssh_service, env_service, command)` | SSH to one host, inject a second service's secrets as env vars |
| `vault_exec(service, command, args)` | Run a local command with secrets as env vars |

There is deliberately no `vault_get`. The agent can never read a secret value — only
act with it.

### Tell your agent how to use it

Drop this in your `CLAUDE.md` (or the equivalent for your agent):

```markdown
## Secrets

Credentials live in vault-mcp. Never ask me to paste a token, never read a `.env`,
never hardcode a credential.

- Check what exists with `vault_list()`.
- To use a credential, call `vault_exec` / `vault_ssh` — they inject it as an env var.
  You will not see the value, and you do not need to.
- If a key you need is missing, tell me to run `vault-mcp add <service> <KEY>`.
- Never run the `vault-mcp` CLI through Bash; use the MCP tools.
```

**Claude Code users:** tool schemas are deferred, so a cold call fails with
`InputValidationError` that looks like the server is down. It isn't. Load the schemas
once per session first:

```
ToolSearch("select:mcp__vault__vault_list,mcp__vault__vault_ssh,mcp__vault__vault_exec")
```

## Secrets vs properties

Two halves of the same encrypted file, so redaction can be aggressive without blanking
out hostnames.

| | Secrets | Properties |
|---|---|---|
| For | passwords, tokens, keys | hosts, ports, usernames, endpoints |
| Input on `add` | hidden | echoed as you type (`-p`) |
| Shown by `list` | key name only | key name **and** value |
| Scrubbed from tool output | yes | no |
| Injected as an env var | yes | yes |

Both halves merge into one environment, so `DB_HOST` (property) and `DB_PASSWORD`
(secret) arrive together. `vault-mcp migrate` bulk-reclassifies address-shaped keys
(`*_HOST`, `*_PORT`, `*_USER`, `*_URL`, `*_ENDPOINT`, `*_BUCKET`, `USERNAME`, `SERVER`)
and asks before writing.

## SSH proxy

Give a service these keys and `vault_ssh` works against it:

| Key | Required | Default |
|---|---|---|
| `SSH_HOST` | yes | — |
| `SSH_PORT` | no | `22` |
| `SSH_USER` | no | `root` |
| `SSH_PASSWORD` | yes | — |

Interactive sessions are refused on purpose — one command per call, so every action is
a discrete auditable step.

## Naming

`<group>/<service>`, e.g. `homeserver/db`, `work/cloudflare`. The group is yours to
define: an environment, a client, a machine. On `unlock`, `homeserver/db` becomes
`~/.vault/decrypted/homeserver-db.env` and `.ps1`.

## Commands

| Command | Description |
|---|---|
| `vault-mcp add <svc> <KEY>` | Add or update a secret (hidden input) |
| `vault-mcp add -p <svc> <KEY>` | Add or update a property (visible input) |
| `vault-mcp list [svc]` | List keys; property values printed, secrets not |
| `vault-mcp remove <svc> <KEY>` | Remove a key |
| `vault-mcp migrate` | Reclassify address-shaped keys as properties |
| `vault-mcp ssh <svc> -- <cmd>` | SSH proxy |
| `vault-mcp exec <svc> -- <cmd>` | Exec with secrets as env vars |
| `vault-mcp unlock` | Write `decrypted/` for scripts that need real env files |
| `vault-mcp lock` | Securely delete `decrypted/` |
| `vault-mcp passwd` | Change the master passphrase |
| `vault-mcp init` | Force first-time setup (normally automatic) |
| `vault-mcp serve` | Start the MCP server on stdio |

## Security model

- **Values are never CLI arguments.** No shell history, no process list.
- **Output is scrubbed.** Every tool result passes through a redactor that replaces
  secret values with `[REDACTED]`. A verbose `curl`, an `env` on a remote host, a shell
  loop that echoes its own command — all blanked before the agent sees them. Values
  under 6 characters are left alone, since replacing them mangles unrelated output.
- **The passphrase is not in the repo.** OS keychain (Windows Credential Manager,
  libsecret, macOS Keychain), falling back to `~/.config/sync-vault/master` at mode
  0600 where no keychain exists (Termux, headless).
- **`unlock` is explicit.** Plaintext only hits disk when a human asks for it.

The redactor is a safety net, not a licence. An agent that can `ssh` as root can still
do damage with the access, just not exfiltrate the credential.

## Building from source

```bash
git clone https://github.com/DomiIRL/vault-mcp
cd vault-mcp
go build -o vault-mcp .
go test ./...
```

## License

MIT

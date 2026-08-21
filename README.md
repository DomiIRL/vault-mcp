# vault-mcp

Keeps your secrets in one age-encrypted file and hands them to an AI coding agent as MCP
tools, so the agent can act with a credential without being able to read it.

The master passphrase lives in your OS keychain, not in the file and not in git. Instead
of values, the agent gets `ssh` and `exec` proxy tools: it asks for a command to run
somewhere, the binary injects the credentials, and the output is scrubbed of every secret
value before the agent sees it.

## Why

An agent that can read a `.env` will sooner or later paste one into a transcript, and a
token you type into a chat window stays in that log for good. A hosted secrets manager
fixes that, at the cost of an account, a bill, and a network dependency for something
that is one file on your disk.

## Install

```bash
go install github.com/DomiIRL/vault-mcp@latest
```

The binary lands in `$(go env GOPATH)/bin`, which needs to be on your `PATH`.

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
├── vault.age     # the encrypted vault, safe to commit or sync
├── index.md      # generated: key names only, no values
└── decrypted/    # only exists between `unlock` and `lock`
```

`vault.age` is fine to put in a private or a public git repo. It is scrypt-encrypted and
useless without the passphrase, and that is the intended way to move it between machines:
clone the repo on the second machine, run any `vault-mcp` command, type the same
passphrase once, done.

## Wire it into Claude Code

```bash
claude mcp add --scope user vault -- "$(go env GOPATH)/bin/vault-mcp" serve
```

`--scope user` registers it globally, so the vault is there in every project instead of
one repo. Restart Claude Code and the tools show up.

For other MCP clients: the server speaks MCP over stdio, so the command is
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

There is deliberately no `vault_get`, so an agent can use a credential but never read one.

### Tell your agent how to use it

Drop this in your `CLAUDE.md`, or the equivalent for whatever agent you run:

```markdown
## Secrets

Credentials live in vault-mcp. Never ask me to paste a token, never read a `.env`,
never hardcode a credential.

- Check what exists with `vault_list()`.
- To use a credential, call `vault_exec` or `vault_ssh`. They inject it as an env var,
  so you will not see the value and do not need to.
- If a key you need is missing, tell me to run `vault-mcp add <service> <KEY>`.
- Never run the `vault-mcp` CLI through Bash; use the MCP tools.
```

In Claude Code, tool schemas are deferred, so the first call fails with an
`InputValidationError` that reads like the server is down. It isn't. Load the schemas
once per session first:

```
ToolSearch("select:mcp__vault__vault_list,mcp__vault__vault_ssh,mcp__vault__vault_exec")
```

## Secrets vs properties

Two halves of the same encrypted file, so redaction can be aggressive without blanking
out your hostnames.

| | Secrets | Properties |
|---|---|---|
| For | passwords, tokens, keys | hosts, ports, usernames, endpoints |
| Input on `add` | hidden | echoed as you type (`-p`) |
| Shown by `list` | key name only | key name and value |
| Scrubbed from tool output | yes | no |
| Injected as an env var | yes | yes |

Both halves merge into one environment, so `DB_HOST` (property) and `DB_PASSWORD`
(secret) arrive together. `vault-mcp migrate` reclassifies address-shaped keys in bulk
(`*_HOST`, `*_PORT`, `*_USER`, `*_URL`, `*_ENDPOINT`, `*_BUCKET`, `USERNAME`, `SERVER`)
and shows you the plan before writing.

## SSH proxy

Give a service these keys and `vault_ssh` works against it:

| Key | Required | Default |
|---|---|---|
| `SSH_HOST` | yes | none |
| `SSH_PORT` | no | `22` |
| `SSH_USER` | no | `root` |
| `SSH_PASSWORD` | yes | none |

Interactive sessions are refused on purpose: one command per call, so every action is a
separate step you can audit afterwards.

## Naming

`<group>/<service>`, for example `homeserver/db` or `work/cloudflare`. The group is yours
to define, whether that is an environment, a client, or a machine. On `unlock`,
`homeserver/db` becomes `~/.vault/decrypted/homeserver-db.env` and `.ps1`.

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
| `vault-mcp init` | Force first-time setup, which normally happens automatically |
| `vault-mcp serve` | Start the MCP server on stdio |

## Security model

Values are never passed as CLI arguments, so they stay out of your shell history and out
of the process list.

Every tool result goes through a redactor that replaces secret values with `[REDACTED]`
before the agent sees it. That catches a verbose `curl`, an `env` on a remote host, or a
shell loop that echoes its own command back. Values shorter than 6 characters are left
alone, because replacing those mangles unrelated output.

The passphrase never goes near the repo. It is stored in the OS keychain (Windows
Credential Manager, libsecret, macOS Keychain), falling back to
`~/.config/sync-vault/master` at mode 0600 where there is no keychain, such as Termux or
a headless box.

Plaintext only reaches disk when you ask for it with `unlock`, and `lock` deletes it
again.

The redactor limits what can leak, not what the agent can do. Something that can `ssh` as
root is still able to do damage with that access. It just cannot walk off with the
credential.

## Building from source

```bash
git clone https://github.com/DomiIRL/vault-mcp
cd vault-mcp
go build -o vault-mcp .
go test ./...
```

## License

MIT

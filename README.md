# 🛡️ Enclave

> *A digital enclave: a fully isolated, encrypted space for your AI conversations.*

**Enclave** is a privacy-first AI CLI where encryption is the main feature, not an afterthought. Like its geographic namesake, your data stays sealed inside.

## Why

Existing AI CLIs store your history in plaintext and your API keys in plain files. Enclave exists to fix that:

| Aspect | Typical AI CLI | Enclave |
|--------|----------------|---------|
| Chat history | ❌ Plaintext on disk | ✅ AES-256 (SQLCipher) |
| API keys | ❌ Plaintext file (`auth.json`) | ✅ OS Keychain |
| Master key | ❌ None | ✅ PBKDF2-SHA256, 600k iterations |
| Telemetry | ⚠️ Unclear | ✅ Zero by default |
| Local models | ⚠️ Limited | ✅ Ollama (100% offline) |

## Security model

- **Zero plaintext at rest** — chat history lives in a SQLCipher database (AES-256, HMAC-SHA512, 256k KDF iterations). Nothing readable without the master key.
- **API keys in the OS keychain** — macOS Keychain, Windows Credential Manager, Linux Secret Service. Never in a file.
- **Password-derived master key** — PBKDF2-HMAC-SHA256 with 600,000 iterations and a random 32-byte salt, zeroized from memory when dropped.
- **Zero telemetry** — no data leaves the machine unless you chat with a remote provider. For sensitive content, use Ollama: fully offline.

## Install

```bash
cargo install --path .
```

## Usage

```bash
# Store an API key (goes to the OS keychain)
enclave keys set openrouter

# Start an encrypted chat
enclave chat --provider openrouter --model mistralai/mistral-large

# Fully offline chat with a local model
enclave chat --provider ollama --model llama3.2

# Full-screen TUI
enclave tui
enclave tui --no-tools   # TUI without shell-proposal prompts

# Manage sessions
enclave sessions list
enclave sessions rename <id> "new name"
enclave sessions delete <id>

# Export/import sessions (encrypted with a dedicated password)
enclave sessions export <id> backup.enclave
enclave sessions import backup.enclave

# Show resolved configuration (no secrets)
enclave config

# Nuke everything (irreversible)
enclave wipe --force
```

## In-chat commands

| Command | Action |
|---------|--------|
| `exit` / `quit` | Leave the chat |
| `clear` | Wipe the current conversation |
| `history` | Show recent messages |

## Tools (shell proposals)

When the assistant includes a fenced ` ```bash ` block, Enclave shows the
command and asks before doing anything:

```text
— the assistant proposed 1 shell command(s); nothing runs without your approval —
$ sw_vers
run? [y]es / [n]o / [a]ll / [q]uit >
```

Built-in guardrails:

- **ask-always**: the default answer is *no*; there is no auto-run mode
- **hard timeout** (30s default) — runaway commands are killed
- **output cap** (8KB default) — truncates display *and* what enters the history
- **`--no-tools`** disables proposals entirely (also `tools.enabled = false` in `config.toml`)
- command output is stored in the encrypted history and will be sent to the
  provider on the next turn — use `--provider ollama` to keep it local

## Privacy Guard (sensitive-data interception)

Before any message reaches a **cloud** provider, Enclave scans it for
sensitive data. Detected categories: emails, phone numbers, IBANs, Italian
tax IDs, card numbers (Luhn-validated), API secrets (`sk-…`, `ghp_…`, AWS,
JWT…) and IP addresses.

```text
⚠ privacy guard — 2 sensitive item(s) detected:
  · email: mario.rossi@gmail.com
  · phone: +39 333 1234567
send [s]as-is / [p]laceholders / [r]efuse >
```

- **as-is**: you explicitly approve this session's content for the network
- **placeholders**: every occurrence is replaced with a stable token
  (`[EMAIL_1]`, `[IBAN_1]`, …) in **every outgoing request**, while the
  original text stays only in the encrypted local history
- **refuse**: the message is not sent; in the TUI it returns to the input
  box for editing

Configuration (`config.toml`):

```toml
[guard]
enabled = true
mode = "ask"   # ask | redact (auto-placeholder) | block (auto-refuse)
```

`--no-guard` disables the scan (not recommended). Detection runs on every
turn — including the whole history that is re-sent — with stable placeholder
numbering, so the model never sees inconsistent tokens.

## TUI keybindings

| Key | Action |
|-----|--------|
| `Enter` | Send message |
| `Alt+Enter` | New line in the input box (multiline) |
| `Esc` / `Ctrl-C` | Quit |
| `Ctrl-L` | Clear the session (wipes encrypted history, starts fresh) |
| `Ctrl-W` / `Ctrl-U` | Delete word / clear input |
| `PgUp` / `PgDn` (or ↑/↓) | Scroll transcript |
| `?` (empty input) | Toggle the shortcuts overlay |
| Mouse wheel | Scroll transcript |
| `Tab` | Toggle focus between chat and the sessions sidebar |
| `↑`/`↓` + `Enter` (sidebar) | Switch to another encrypted session |
| `n` (sidebar) | Create a new encrypted session |
| `r` (sidebar) | Rename the selected session |
| `d` (sidebar) | Delete the selected session (the active one is protected) |
| `y` / `n` / `a` / `q` | Approve / deny / approve-all / skip shell proposals |
| `s` / `p` / `r` / `Esc` (guard overlay) | Send as-is / placeholders / refuse sensitive data |

Slash commands (typed in the message box, executed locally, never sent to the provider):

| Command | Action |
|---------|--------|
| `/help` | Command list |
| `/new` | Create a new session |
| `/switch` | Open the sessions sidebar |
| `/clear` | Wipe the current session history |
| `/model <id>` | Switch model for this run (`/model` alone shows the current one) |
| `/quit` | Exit Enclave |

The TUI renders an opencode-style layout: a header bar, a sessions sidebar
(28 columns, hidden on narrow terminals), a styled transcript with markdown
rendering for assistant replies (headings, bold, inline code, code blocks
with gutter, lists, quotes), a spinner while streaming, and a yellow panel
for shell proposals — same ask-always security model as the CLI.
The sidebar shows ● for the active session and ○ for the others.

## Useful commands

| Command | What it does |
|---------|--------------|
| `enclave models` | Browse the live OpenRouter catalogue (table: id, name, context, $/Mtok, FREE) |
| `enclave models --search gpt --free --limit 20` | Filter the catalogue |
| `enclave models --set <model-id>` | Validate + save a model as default (config.toml) |
| `enclave db` | Unlock and show database stats: file size, SQLCipher pages, freed pages, sessions, messages |
| `enclave sessions delete <id> --purge` | Delete a session **and** compact the DB (freed ciphertext removed) |
| `enclave sessions wipe-all` | Delete ALL sessions + compact (asks confirmation) |
| `enclave sessions vacuum` | Reclaim disk space from deleted ciphertext |

Security/privacy audit: see [docs/audit.md](docs/audit.md).

## Privacy notes

Chatting through a **remote provider (OpenRouter, OpenAI, Anthropic) means your prompt leaves the device in transit** — encryption at rest protects your local history, not the network hop. Providers may also apply their own content scanning (e.g. OpenRouter PII detection).

For genuinely sensitive conversations, run a local model:

```bash
ollama pull llama3.2
enclave chat --provider ollama
```

### Encrypted backups

`enclave sessions export` writes a portable `.enclave` file: a JSON payload
(session name + messages) encrypted with AES-256-GCM under a dedicated export
password (PBKDF2, fresh random salt per export — independent from your master
password). The file contains **zero plaintext**; import it on another machine
with `enclave sessions import` (the session is recreated with a new id).

## Development

```bash
cargo test        # encryption, session and vault integration tests
cargo build       # debug build
```

Architecture and design details live in [`docs/`](docs/).

### macOS keychain prompts on every launch

The binary touches the keychain twice per launch (API key + master key). If
`dist/enclave` is **unsigned**, macOS cannot remember an "Always Allow" grant
(the code signature changes on every rebuild) and re-asks the keychain
password for each item at every launch. Fix:

```bash
codesign --force --sign - dist/enclave   # ad-hoc sign (included below)
```

then on the next launch choose **Always Allow** (not just *Allow*) for both
items. The grant persists until the binary is rebuilt; re-sign after every
rebuild. For a grant that also survives rebuilds, create a self-signed
code-signing certificate (Keychain Access → Certificate Assistant → Create a
Certificate → type *Code Signing*, e.g. name `enclave-local`) and sign with
`codesign --force --sign enclave-local dist/enclave` instead.

## License

MIT — see [LICENSE](LICENSE).
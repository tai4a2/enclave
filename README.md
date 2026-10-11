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

# ...or provide it via an environment variable (no keychain prompt at all)
export ENCLAVE_OPENROUTER_API_KEY=sk-or-...
# also recognized: OPENROUTER_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY

# Start an encrypted chat
enclave chat --provider openrouter --model mistralai/mistral-large-4-0

# Fully offline chat with a local model
enclave chat --provider ollama --model llama3.2

# Full-screen TUI
enclave tui
enclave tui --no-tools   # TUI without shell-proposal prompts
enclave tui --agent      # agentic tool loop (read/write/edit files, shell)
enclave tui --effort high  # reasoning effort hint (low|medium|high)

# Attach a file to the first message (image for multimodal models, or text)
enclave chat --attach ./diagram.png --attach ./notes.md

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

## Agentic mode (function calling)

Beyond markdown *proposals*, Enclave supports real function calling: the
model receives a typed tool schema and returns structured tool calls that
Enclave executes for it, feeding results back until the task is done.

```bash
enclave chat --agent                      # built-in tools + ask-always approvals
```

Built-in tools (workspace-restricted, human-approved):

| Tool | What it does |
|------|--------------|
| `read_file` | Read a file inside the workspace (output capped) |
| `write_file` | Write a file inside the workspace (path traversal rejected) |
| `list_dir` | List a directory inside the workspace |
| `run_shell` | Run a shell command (same timeout + output cap as proposals) |

Guardrails: every call needs explicit approval (`[y]es/[n]o/[a]ll/[q]uit`,
ask-always), paths are canonicalized and confined to the current directory,
`..` and absolute paths outside the workspace are rejected, max 8 tool
iterations per turn. The privacy guard redacts tool arguments/results the
same way as chat text.

### Multi-agent (delegate)

Define sub-agents in `config.toml` — each with its own provider/model/persona
(sub-agent sessions are ephemeral: RAM-only, never written to disk):

```toml
[agent.personas.researcher]
provider = "openrouter"
model = "mistralai/mistral-large-4-0"
system_prompt = "You research topics and report facts back concisely."

[agent.personas.writer]
provider = "ollama"
model = "llama3.2:1b"
system_prompt = "You turn research notes into short summaries."
```

The main agent then gets a `delegate(agent, task)` tool: it can hand
subtasks to sub-agents and collect their results. Depth limit: sub-agents
cannot delegate further (no fan-out explosions). Example:

```bash
enclave chat --agent
you> use the researcher agent to summarize the state of encrypted messaging, then have the writer produce a tweet-length summary
```

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
| `Ctrl-S` | Open the session picker overlay (works at any terminal size) |
| `↑`/`↓` + `Enter` (sidebar or picker) | Switch to another encrypted session |
| `n` (sidebar or picker) | Create a new session — asks for a name first |
| `r` (sidebar or picker) | Rename the selected session (inline prompt) |
| `d` (sidebar or picker) | Delete the selected session (the active one is protected) |
| Mouse click (sidebar row) | Open that session |
| `y` / `n` / `a` / `q` | Approve / deny / approve-all / skip shell proposals |
| `s` / `p` / `r` / `Esc` (guard overlay) | Send as-is / placeholders / refuse sensitive data |

Slash commands (typed in the message box, executed locally, never sent to the provider):

| Command | Action |
|---------|--------|
| `/help` | Command list |
| `/new` | Create a new session (asks for a name) |
| `/switch` | Open the session picker overlay (also `Ctrl-S`) |
| `/clear` | Wipe the current session history |
| `/model` | Open the model picker (type to filter, ↑/↓/PgUp/PgDn select, Enter choose, Esc close) — the choice is saved for next launches |
| `/model <id>` | Switch model directly (saved for next launches) |
| `/models` | Alias of `/model` (opens the picker) |
| `/effort` | Set reasoning effort: `off` · `low` · `medium` · `high` (saved) |
| `/attach <path>` | Attach an image or text file to your next message |
| `/detach` | Clear pending attachments |
| `/credits` | Show OpenRouter credit / usage / limits (also `/usage`) |
| `/quit` | Exit Enclave |

The TUI renders an opencode-style layout: a header bar, a sessions sidebar
(28 columns, hidden on narrow terminals — use `Ctrl-S` there), a styled
transcript with markdown rendering for assistant replies (headings, bold,
inline code, code blocks with gutter, lists, quotes), a spinner while
streaming, and a yellow panel for shell proposals — same ask-always security
model as the CLI. The sidebar shows ● for the active session and ○ for the
others. Sessions are named when you create them (an empty name becomes
`chat`). On launch Enclave **reopens the most recently used session**, so
past conversations come back; the chosen **model** and **reasoning effort**
(`/effort`) are saved in `config.toml` and reused next time.

When the terminal is at least **110 columns** an **info panel** appears on the
right with live details: session name/id, model and provider, a context
estimate, OpenRouter credits, tools/guard state, the encrypted database size,
message/session counts, and a **CHANGES** list (`+added −removed` per file).

### Attachments

Use `/attach <path>` (or `--attach <path>` in the CLI) to add a **file** to
your next message. **Images** (`png`/`jpg`/`gif`/`webp`) are sent to the model
as multimodal content — use a vision model (e.g. `openai/gpt-4o`,
`anthropic/claude-3-5-sonnet`, `google/gemini-*`, or a local `ollama` model
such as `llava`). **Text files** (`.txt`/`.md`/`.json`/`.csv`/code…) are
inlined into the prompt, so they are also scanned by the privacy guard.
Attachments are stored **encrypted** inside the SQLCipher database (images as
base64) and never leave the machine unencrypted; images are capped at 8 MB.
`/detach` clears pending attachments.

With `--agent` the assistant uses the built-in tools (`read_file`,
`write_file`, `edit_file`, `list_dir`, `run_shell`) through real function
calling. Every call is shown in a yellow panel titled *"tool call — nothing
runs without your approval"* and waits for your `y`/`n`/`a`/`q`. File edits
are rendered inline in the transcript as **diffs** (green `+added`, red
`−removed` lines) and are summarised in the info panel's CHANGES list.

A **privacy bar** above the footer always shows live information:
the encrypted database size on disk, the number of sessions and messages,
the cipher, and whether the privacy guard is active. For OpenRouter the
header additionally shows account info (credits used, remaining, limits).
API keys are read from `ENCLAVE_<PROVIDER>_API_KEY` / `<PROVIDER>_API_KEY`
or the local `keys.toml` (mode `0600`) — the OS keychain is only a fallback,
so macOS does not prompt on every launch. By default the master password is
asked only the first time: the derived key is cached in the local `keys.toml`
(`use_keychain = true`, mode `0600`), so later launches skip it with **no**
OS-keychain dialog. Set `use_keychain = false` to require the password on every
launch.

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

The API key is read lazily (on the first message, not at startup) and the
master key is **not** cached by default, so a normal launch touches the
keychain at most once. If `dist/enclave` is **unsigned**, macOS cannot
remember an "Always Allow" grant (the code signature changes on every
rebuild) and re-asks the keychain password. Fix:

```bash
codesign --force --sign - dist/enclave   # ad-hoc sign (included below)
```

then on the next launch choose **Always Allow** (not just *Allow*). The grant
persists until the binary is rebuilt; re-sign after every rebuild. For a grant
that also survives rebuilds, create a self-signed code-signing certificate
(Keychain Access → Certificate Assistant → Create a Certificate → type *Code
Signing*, e.g. name `enclave-local`) and sign with
`codesign --force --sign enclave-local dist/enclave` instead.

To avoid the keychain entirely, export the key as an environment variable
(`ENCLAVE_OPENROUTER_API_KEY` or the provider's standard `*_API_KEY`); Enclave
prefers it over the keychain.

## License

MIT — see [LICENSE](LICENSE).
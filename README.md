# 🛡️ Enclave

> *A digital enclave: a fully isolated, encrypted space for your AI conversations.*

**Enclave** is a privacy-first AI CLI where encryption is the main feature, not an afterthought. Like its geographic namesake, your data stays sealed inside.

## Why

Existing AI CLIs store your history in plaintext and your API keys in plain files. Enclave exists to fix that:

| Aspect | Typical AI CLI | Enclave |
|--------|----------------|---------|
| Chat history | ❌ Plaintext on disk | ✅ AES-256 (SQLCipher) |
| API keys | ❌ Plaintext file (`auth.json`) | ✅ OS Keychain |
| Master key | ❌ None | ✅ Argon2id (or PBKDF2) + mlock/no-swap |
| Telemetry | ⚠️ Unclear | ✅ Zero by default |
| Local models | ⚠️ Limited | ✅ Ollama (100% offline) |

## Security model

- **Zero plaintext at rest** — chat history lives in a SQLCipher database (AES-256, HMAC-SHA512, 256k KDF iterations). Nothing readable without the master key.
- **API keys in the OS keychain** — macOS Keychain, Windows Credential Manager, Linux Secret Service. Never in a file.
- **Password-derived master key** — Argon2id (memory-hard) by default, PBKDF2-HMAC-SHA256 (600k) for legacy vaults, with a random 32-byte salt. The key is zeroized on drop and `mlock`-ed so it never hits swap; core dumps are disabled.
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
enclave tui --plan       # start in Plan mode (read-only, proposes steps)
enclave chat --agent --auto  # auto-approve tools not explicitly denied

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

## Long-term memory (Supermemory)

Enclave keeps a **local, encrypted memory** of facts, preferences and notes
that persists across sessions and is injected into the system prompt. It lives
in the same SQLCipher `vault.db` as your conversations — nothing is sent to an
external memory service.

In the TUI:

| Command | Action |
|---------|--------|
| `/remember <text> #tag` | Save a fact (`--local` keeps it off the network) |
| `/memory` | List memories (`/memory search <q>` to search, `/memory pin <id>`) |
| `/forget <id\|text>` | Delete a memory by id or by matching text |
| `/checkpoint` | Summarise the current session into long-term memory |

From the CLI:

```bash
enclave memory add "prefers Rust" --tags langs
enclave memory list
enclave memory search rust
enclave memory pin <id>          # also: --off to unpin
enclave memory forget <id|text>
enclave memory clear --force
```

Configuration (`config.toml`):

```toml
[memory]
enabled = true          # inject memories into the system prompt
inject_limit = 50       # max memories injected
autosave_secs = 0       # >0 = periodically checkpoint the session (opt-in)

# The session Enclave reopens on launch (set automatically as you switch).
working_session = "9f3c1a2b-…"
```

- **Injection**: the most relevant memories (pinned first, then most recent)
  are added to the system prompt, up to `inject_limit`. Injected text is
  context like any other, so the **privacy guard applies** before it goes to a
  cloud provider.
- **`--local` / `local_only`**: such memories are stored but **never injected**
  into requests that leave the machine.
- **Agent tool**: in agentic mode the model can save memories itself via the
  `remember` tool (permission-gated).
- **Working session**: Enclave remembers which session you were in and reopens
  it on the next launch.

## Security hardening

Wave A of the [security roadmap](docs/security-roadmap.md) is implemented.

**Master key.** New vaults derive the master key with **Argon2id** (memory-hard).
Legacy PBKDF2 vaults keep working (the algorithm is recorded in the salt header).
Set the default for *new* vaults with `kdf = "argon2id" | "pbkdf2"`. The key is
held in a `mlock`-ed heap buffer (never swapped) and zeroized on drop; core dumps
are disabled at startup.

**Egress ledger.** Every request that leaves the machine is recorded — in the
encrypted `vault.db` — as a SHA-256 fingerprint plus the model, timestamp and the
guard's redaction map. **No payload or secret is ever stored in clear.** The chain
is tamper-evident:

```bash
enclave ledger            # list recent egresses (fingerprints only)
enclave ledger --verify   # verify the hash chain (exit 2 if tampered)
```

In the TUI the privacy bar shows the egress count and `/ledger` opens the list.

**Locking and clipboard.** In the TUI:

| Behaviour | Config | Default |
|-----------|--------|---------|
| Auto-lock after inactivity (hides the transcript behind the master password) | `[security] auto_lock_secs` | `0` (off) |
| Clipboard auto-clear after copying from Enclave | `[security] clipboard_clear_secs` | `30` s |
| Blur the view when the window loses focus | always on | — |
| Instant lock + hide | `/panic` | — |

The clipboard is cleared only if it still holds the text Enclave copied.

**Duress password.** Set `ENCLAVE_DURESS_PASSWORD` in your environment; typing
that password at the master-password prompt opens a **separate decoy vault**
(`<config>/decoy/`) instead of the real one. It is never written to `config.toml`.

```toml
[security]
auto_lock_secs = 300        # lock the TUI after 5 minutes idle (0 = off)
clipboard_clear_secs = 30   # clear Enclave-copied clipboard text after 30s
```

**Command sandbox.** On macOS, the shell commands you approve (markdown
proposals, the agentic `run_shell` tool, and `!command`) run inside a
`sandbox-exec` jail: file reads are allowed, but writes are restricted to the
workspace and temporary directories. Set `[tools] sandbox = "strict"` to also
block network access, `"fs"` for the file jail only, `"off"` to disable it, or
`"auto"` (default) to use the strongest sandbox the platform supports.

```toml
[tools]
sandbox = "auto"   # auto | off | fs | strict
```

**Taint tracking.** When the privacy guard detects sensitive data in a message
you send, that message is flagged *tainted* and stored that way. On every later
turn the engine automatically re-redacts tainted messages (stable placeholders
like `[EMAIL_1]`) before they leave for a **remote** provider — without asking
again and regardless of the per-message guard choice — so once a secret has
entered the conversation it can never travel verbatim in a subsequent request.
Set `[guard] taint = false` to disable this. Local (Ollama) sessions are
unaffected: nothing leaves the machine.

**Egress policy (policy-as-code).** A local, declarative policy can force how
each class of sensitive data may leave the machine. Define rules per data kind
in `[policy]`; before any request to a **remote** provider the engine scans the
outbound messages and applies the *strictest* matching action — `allow`,
`redact` (placeholders) or `block` (the turn is refused). Local (Ollama)
providers are never restricted. Example:

```toml
[policy]
enabled = true
default = "allow"            # action for kinds without a rule

[policy.rules]
email = "redact"
phone = "redact"
iban = "block"
card = "block"
secret = "block"
tax_id = "block"
ip = "allow"
```

Recognised keys: `email`, `phone`, `iban`, `tax_id`, `card`, `secret`, `ip`.

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
| `read_file` | Read a file inside the workspace (optional `offset`/`limit` line range, output capped) |
| `write_file` | Write a file inside the workspace (path traversal rejected) |
| `edit_file` | Replace an exact `old_string` with `new_string` (fails if missing or ambiguous) |
| `apply_patch` | Apply a unified diff (multi-hunk) to a file in one call |
| `list_dir` | List a directory inside the workspace |
| `glob` | Find files by glob pattern (`**/*.rs`, `src/*.toml`, …) |
| `grep` | Search file contents by regular expression (optional `glob` filter) |
| `run_shell` | Run a shell command (same timeout + output cap as proposals) |
| `todo` | Record/update a task list (shown in the info panel) |
| `question` | Ask you a multiple-choice question mid-task (interactive in the CLI) |

File writes/edits return an inline diff (green `+` / red `−`) which is also
recorded in the info panel **CHANGES** list.

Guardrails: every call needs explicit approval (`[y]es/[n]o/[a]ll/[q]uit`,
ask-always), paths are canonicalized and confined to the current directory,
`..` and absolute paths outside the workspace are rejected, max 8 tool
iterations per turn. The privacy guard redacts tool arguments/results the
same way as chat text.

### Rules (`AGENTS.md`)

Enclave automatically loads local rule files into the system prompt — all
resolved **locally**, never fetched from the network:

| Location | Scope |
|----------|-------|
| `<config_dir>/AGENTS.md` | Global instructions (e.g. `~/.config/enclave/AGENTS.md`) |
| nearest `AGENTS.md` walking up from the cwd to the git root | Project instructions |
| `instructions = ["docs/STYLE.md", ...]` in `config.toml` | Extra local files (relative to the cwd; `http(s)://` entries are ignored) |

The nearest project file wins per category; global and project rules are
concatenated, then any `instructions` entries. Remote URLs are never fetched.

### Permissions

Tool calls are gated by a `[permissions]` table in `config.toml`. Each rule
is `allow`, `ask` or `deny`:

```toml
[permissions]
read = "allow"        # read_file
write = "ask"         # write_file / edit_file
bash = "ask"          # run_shell
default = "ask"       # fallback for tools without a specific rule
external_directory = "ask"  # any path outside the workspace

[permissions.bash_rules]
"git status *" = "allow"
"rm *" = "deny"
```

Defaults are read-only friendly: `read_file`/`list_dir`/`glob`/`grep` are
`allow`, mutations (`write_file`/`edit_file`/`run_shell`/`delegate`) are
`ask`, and `external_directory` is `ask`. `bash_rules` entries are matched
against the parsed command; the **longest** matching pattern wins (ties go
to the most restrictive). `--auto` (CLI) auto-approves anything not
explicitly denied; a repeated identical tool call (`doom_loop`) can be gated
to break loops.

### Plan / Build mode

Like opencode, Enclave has two modes:

- **build** (default): all tools available.
- **plan**: read-only — `write_file`, `edit_file`, `run_shell` and `delegate`
  are refused, and a planning note is added to the system prompt so the model
  analyses and proposes steps instead of changing anything.

Switch with `Shift+Tab` in the TUI, the `/plan` and `/build` slash commands,
or the `--plan` flag on `enclave chat` / `enclave tui`. The current mode is
shown in the info panel.

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
| `Ctrl-Y` | Copy mode: select transcript lines (↑/↓, PgUp/PgDn, Home/End) and press `y` to copy to the clipboard — `a` selects all, `e` copies the last reply |
| `Ctrl-P` / `Ctrl-N` | Recall previous / next message from the input history |
| `Ctrl-F` | Find text in the current conversation (type to search, Enter copies the line) |
| `Ctrl-R` | Search text across **all** saved sessions (Enter opens the session) |
| `Ctrl-O` | Edit the message box in `$EDITOR` (`$VISUAL` → `vi`) |
| `Ctrl-L` | Clear the session (wipes encrypted history, starts fresh) |
| `Ctrl-W` / `Ctrl-U` | Delete word / clear input |
| `PgUp` / `PgDn` (or ↑/↓) | Scroll transcript |
| `?` (empty input) | Toggle the shortcuts overlay |
| Mouse wheel | Scroll transcript |
| `Tab` | Toggle focus between chat and the sessions sidebar |
| `Shift+Tab` | Toggle Plan / Build mode |
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
| `/plan` / `/build` | Switch to Plan (read-only) / Build mode |
| `/copy [n]` | Copy the last reply (or the last `n` replies) to the clipboard |
| `/save [path]` | Save this conversation as a Markdown file (plaintext, not encrypted) |
| `/undo` | Remove the last user turn and put it back in the input box |
| `/redo` | Restore the text removed by the last `/undo` |
| `/retry` | Undo the last turn and resend the same message |
| `/compact` | Summarise the conversation and replace the history with the summary |
| `/commands` | List your custom commands (see below) |
| `/find <text>` | Search the current conversation (also `Ctrl-F`) |
| `/search <text>` | Search across all saved sessions (also `Ctrl-R`) |
| `/export [md\|html\|pdf] [path]` | Export this conversation (HTML/Markdown native; PDF needs `pandoc`/`wkhtmltopdf`) |
| `/editor` | Open the message box in `$EDITOR` (also `Ctrl-O`) |
| `/init` | Generate an `AGENTS.md` for this project from its files |
| `/mcp` | List tools exposed by connected MCP servers |
| `/theme [name]` | Show or switch the colour theme (`default` · `nord` · `gruvbox` · `solarized` · `mono`) — saved |
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

### In-chat helpers

Beyond slash commands the message box understands two shorthands, both resolved
locally and never sent to the provider as raw code:

- **`@file`** — mention a file by path (`@src/main.rs`, `@README.md`) and its
  content is attached to your message. If the token is not a real path, Enclave
  matches it against the workspace file list (by relative path, filename, or
  suffix) and attaches the best hit; an unmatched `@token` is left untouched.
- **`!command`** — a message starting with `!` runs as a **local shell command**
  (same ask-always sandbox, timeout and output cap as tools) and prints the
  output into the transcript. It is never forwarded to the model, so the output
  stays on your machine.

### Custom commands

Drop Markdown files in `.enclave/commands/` (project) or
`<config_dir>/commands/` (global) — project commands override global ones of
the same name. The filename is the command name; an optional front-matter block
sets its metadata:

```markdown
---
description: Review a file for issues
agent: reviewer
---
Review $1 for bugs and style problems. Focus on $ARGUMENTS.
```

Invoke it as `/your-command some arguments` in the TUI or CLI. `$ARGUMENTS`
expands to everything after the command name, and `$1`…`$9` to individual
whitespace-separated arguments. Custom commands are **local files only** —
remote URLs are ignored, exactly like `AGENTS.md` rules.

### Themes and keybindings

```toml
# config.toml
[tui]
theme = "nord"            # default | nord | gruvbox | solarized | mono
notify = true             # terminal bell + macOS notification when a reply
                          # or a tool approval is ready (default true)

[tui.keybinds]            # override built-in keys (action = key spec)
quit          = "ctrl+q"
copy          = "ctrl+y"
session_picker = "ctrl+s"
toggle_mode   = "ctrl+t"
```

Recognised actions: `quit`, `clear`, `copy`, `session_picker`, `toggle_sidebar`,
`toggle_mode`, `newline`, `history_prev`, `history_next`, `delete_word`,
`clear_input`, `send`, `session_search`, `edit_input`. Key specs accept
`ctrl`/`alt`/`shift` modifiers plus key names (`enter`, `esc`, `tab`, `space`,
`backspace`, `up`, `down`, `f1`…`f12`, a single character, …). `/theme` also
switches the palette at runtime.

### MCP servers

Enclave can use tools from [Model Context Protocol](https://modelcontextprotocol.io)
servers over stdio. Add them to `config.toml`:

```toml
[mcp.servers.filesystem]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"]

[mcp.servers.weather]
command = "uvx"
args = ["mcp-server-weather"]
env = { API_KEY = "..." }
```

At startup Enclave connects to each server, performs the `initialize` handshake
and lists its tools; every one is exposed as `mcp__{server}__{tool}` and gated by
the permission model (default: **ask**). `/mcp` lists the connected tools. MCP
tool results flow through the same privacy guard, but remember they are produced
by a third-party process — only connect servers you trust.

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
`write_file`, `edit_file`, `apply_patch`, `list_dir`, `glob`, `grep`,
`run_shell`, `todo`, `question`, plus any MCP tools) through real function
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
| `enclave ledger` | Show the encrypted egress ledger — what left the machine (fingerprints only) |
| `enclave ledger --verify` | Verify the ledger hash chain (exit 2 if tampered) |
| `enclave memory add\|list\|search\|pin\|edit\|forget\|clear` | Manage the local encrypted Supermemory |

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
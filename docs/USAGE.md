# Enclave — Usage Manual

**Enclave** is a privacy-first AI coding assistant for the terminal. Your
conversations live in an encrypted SQLCipher vault, your API keys live in the
OS keychain (or an environment variable), and nothing leaves your machine
unless *you* send it to a remote provider. This document is the full user
manual: the command-line interface, the TUI, the local web UI, the line-based
chat, the privacy machinery, memory, Conversation Git, export/search and the
`config.toml` reference.

> New here? Read the project [`README.md`](../README.md) first, then
> [`docs/privacy.md`](privacy.md) for the threat model and [`docs/tools.md`](tools.md)
> for the tool-execution security model.

---

## Table of contents

1. [Command-line interface](#command-line-interface)
2. [TUI guide](#tui-guide)
3. [Web UI guide](#web-ui-guide)
4. [Chat CLI](#chat-cli)
5. [Privacy features in practice](#privacy-features-in-practice)
6. [Memory & project knowledge](#memory--project-knowledge)
7. [Conversation Git](#conversation-git)
8. [Export & search](#export--search)
9. [Configuration (`config.toml`)](#configuration-configtoml)
10. [Common tasks](#common-tasks)

---

## Command-line interface

```text
$ enclave --help
Privacy-first AI CLI with encrypted memory

Usage: enclave <COMMAND>

Commands:
  chat       Start an encrypted chat (line-based)
  tui        Launch the full-screen terminal UI
  keys       Manage API keys in the OS keychain
  models     Browse the OpenRouter model catalogue and pick a default
  db         Show encrypted-database information (size, stats, encryption)
  sessions   Manage encrypted sessions
  memory     Manage the encrypted local memory (facts remembered across sessions)
  ledger     Show the encrypted egress ledger (what left the machine — fingerprints only)
  decisions  Record and recall project decisions (ADR-style encrypted log)
  exposure   Show the privacy blast-radius and a privacy posture score
  context    Explain what Enclave puts into the context this turn ("why is this in context?")
  rag        Manage the local encrypted RAG index (index files, search offline)
  or         OpenRouter account, generation stats and provisioning-key management
  config     Show the resolved configuration (no secrets)
  serve      Serve the local-only web UI (interactive, styled like the TUI)
  wipe       Securely delete the encrypted database, salt and stored keys
  help       Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

Every subcommand accepts `-h`/`--help`; the sections below summarise the flags
and give copy-pasteable examples.

### `chat` — line-based encrypted chat

| Flag | Meaning |
|------|---------|
| `-m, --model <MODEL>` | Model id for this session |
| `-p, --provider <PROVIDER>` | `openrouter` · `openai` · `anthropic` · `ollama` |
| `-s, --session <SESSION>` | Resume/open a specific session id |
| `--no-keychain` | Do not read/write the master key from the OS keychain |
| `--no-tools` | Ignore shell commands proposed by the assistant |
| `--no-guard` | Send without the privacy-guard scan (not recommended) |
| `--agent` | Agentic mode: real function calling with the built-in tools |
| `--effort <low\|medium\|high>` | Reasoning-effort hint |
| `--attach <PATH>` | Attach a file to the first message (repeatable) |
| `--auto` | Auto-approve tool calls unless the permission policy denies them |
| `--plan` | Plan mode: read-only, mutating tools are refused |
| `--air-gap` | Refuse to send anything to a remote provider (local only) |

```bash
enclave chat --provider openrouter --model <model-id>
enclave chat --provider ollama --model llama3.2
enclave chat --agent --auto
enclave chat --attach ./diagram.png --attach ./notes.md
```

### `tui` — full-screen terminal UI

Accepts the same session flags as `chat` (`-m`, `-p`, `-s`, `--no-keychain`,
`--no-tools`, `--no-guard`, `--agent`, `--effort`, `--auto`, `--plan`,
`--air-gap`). See the [TUI guide](#tui-guide).

```bash
enclave tui
enclave tui --agent --plan
enclave tui --provider ollama
```

### `keys` — API keys

Keys are stored in the local `keys.toml` (mode `0600`) by default; `--keychain`
stores them in the OS keychain instead. `keys get` prints only a short prefix.

```bash
enclave keys set openrouter            # prompt for the key
enclave keys set openai --keychain     # store in the OS keychain
enclave keys get openrouter
enclave keys list
enclave keys delete openrouter
```

Environment variables take precedence over stored keys:
`ENCLAVE_<PROVIDER>_API_KEY` or the provider's standard `<PROVIDER>_API_KEY`
(e.g. `OPENROUTER_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`).

### `models` — browse / set the default model

```bash
enclave models
enclave models --search gpt --free --limit 20
enclave models --set <model-id>        # validate + save as default
```

| Flag | Meaning |
|------|---------|
| `-s, --search <TEXT>` | Filter by substring (id or name) |
| `-S, --set <ID>` | Set this model as default (validated) |
| `-l, --limit <N>` | Max rows (default `30`) |
| `--free` | Show only free models |

### `db` — database information

```bash
enclave db      # unlock and print size, pages, sessions, messages
```

### `sessions` — encrypted sessions & Conversation Git

```bash
enclave sessions list
enclave sessions show [<id>]
enclave sessions rename <id> "new name"
enclave sessions delete <id> --purge
enclave sessions wipe-all --force
enclave sessions vacuum
```

Conversation Git and provenance subcommands (`branch`, `log`, `diff`, `merge`,
`provenance`) are covered in [Conversation Git](#conversation-git); export and
import in [Export & search](#export--search).

### `memory` — encrypted long-term memory

```bash
enclave memory add "prefers Rust" --tags langs
enclave memory add "internal codename" --local-only
enclave memory list
enclave memory search rust
enclave memory pin <id>            # --off to unpin
enclave memory edit <id> --text "…" --tags "…"
enclave memory forget <id|text>
enclave memory clear --force
```

### `ledger` — encrypted egress ledger

```bash
enclave ledger                 # list recent egresses (fingerprints only)
enclave ledger --verify        # verify the hash chain (exit 2 if tampered)
enclave ledger --proof <id>    # proof-of-redaction for one entry
enclave ledger -l 50
```

### `decisions` — ADR-style project log

```bash
enclave decisions add "Mistral over Llama" --body "better tool-calling" --tags ai
enclave decisions list
enclave decisions search tool
enclave decisions status <id> superseded
enclave decisions forget <id|text>
```

Statuses: `accepted` · `proposed` · `rejected` · `superseded`.

### `exposure` — blast-radius & posture score

```bash
enclave exposure            # whole vault
enclave exposure --session  # most recent session only
```

Shows counts and kinds only — never payloads or secrets.

### `context` — "why is this in context?"

```bash
enclave context                 # working session
enclave context --session <id>  # a specific session
```

Breaks the outgoing request into labelled parts (system prompt, local
`AGENTS.md` rules, Plan note, injected memory, decisions, anti-injection
notice) with previews and sizes, plus history size, active redactions, taint
status and a token-budget bar when `[context] budget_tokens` is set.

### `checkpoint` — workspace snapshots & rewind

Snapshots the working directory into a private local *shadow* git repo (in the
app data dir — never the project's own `.git`, never the network). A snapshot
is taken automatically before every agentic file edit, and rewinding is itself
a new snapshot, so history stays **linear and reversible**.

```bash
enclave checkpoint list                 # recent snapshots (id, when, label)
enclave checkpoint create "wip"         # record a snapshot now
enclave checkpoint create               # label defaults to "manual checkpoint"
enclave checkpoint diff <id>            # what a snapshot changed
enclave checkpoint restore <id>         # rewind (a safety snapshot is taken first)
```

In the TUI: `/snapshots` (list), `/snapshot [label]` (record), `/rewind <id|n>`
(restore; `n` is the position shown by `/snapshots`). In the web UI use the
**snapshots** toolbar button (list with a ↺ restore action) or the same slash
commands. Disable with `[checkpoints] enabled = false`.

### `verify` — run the project's checks locally

After agentic file edits Enclave can run your project's own checks **locally**
and feed failures back to the model so it fixes them automatically. The command
is auto-detected from `Cargo.toml` (`cargo test`), `package.json` (`npm test`),
`pyproject.toml` (`pytest -q`), `go.mod` (`go test ./...`) or a `Makefile` test
target. It runs with normal access (like CI) so tools that spawn helpers work;
pass `--sandbox` to jail it.

```bash
enclave verify                          # run the detected checks
enclave verify --command "cargo clippy --all-targets"
enclave verify --sandbox                # run it inside the command sandbox
```

Exits non-zero when verification fails. In the TUI: `/verify`. In the web UI:
the **verify** toolbar button or `/verify`.

### `worktree` — git worktrees

One working directory per branch, so several tasks can be in flight at once
without stashing. Local `git` only.

```bash
enclave worktree list
enclave worktree add feature-x                  # <data>/worktrees/feature-x on a new branch
enclave worktree add feature-x --base main      # fork from a revision
enclave worktree add feature-x --path ~/wt/x    # custom location
enclave worktree remove feature-x --force
```

TUI: `/worktree` (list), `/worktree new <name>`, `/worktree use <name>`
(switch the agent workspace to that worktree), `/worktree remove <name>`.
Web UI: the **worktree** toolbar button, or `/worktree`.

### Agent Skills — local instruction packs

Drop a `SKILL.md` in `.enclave/skills/<name>/` (project) or
`<config>/skills/<name>/` (global). Front-matter carries `name` and
`description`; the body is the instruction. Only the name + description enter
the context — the body is loaded on demand by the model through the `skill`
tool. TUI: `/skills` and `/skill <name>`. Web UI: the **skills** button.

```markdown
---
name: deploy
description: How to cut a release
---
1. run the tests
2. run the release script
```

### Repository map — files and their symbols

A compact offline summary (`path: symbols`) built with language-specific
patterns (Rust, Python, JS/TS, Go, generic). A bounded version is injected into
the context when `[context] repomap = true` (default); the model can also ask
for a filtered map with the `repo_map` tool. TUI: `/repomap`.

### `rag` — local encrypted file index

```bash
enclave rag index ./docs ./src
enclave rag index ./docs --replace
enclave rag search "how does the guard work" --limit 5
enclave rag status
enclave rag clear --force
```

### `or` — OpenRouter account & provisioning keys

```bash
enclave or credits
enclave or generation <id>
enclave or activity [YYYY-MM-DD]
enclave or providers
enclave or endpoints <model>
enclave or keys list
enclave or keys create <name> --limit 10
enclave or keys get <hash>
enclave or keys update <hash> --disabled true
enclave or keys delete <hash>
```

`or keys` requires a provisioning key (`ENCLAVE_OPENROUTER_PROVISIONING_KEY`).

### `config` — resolved configuration

```bash
enclave config      # prints the resolved settings (no secrets)
```

### `serve` — local web UI

```bash
enclave serve            # binds 127.0.0.1:7878
enclave serve -p 9000    # custom port
```

See the [Web UI guide](#web-ui-guide).

### `wipe` — irreversible delete

```bash
enclave wipe --force    # deletes the encrypted DB, salt and stored keys
```

---

## TUI guide

Start the full-screen UI:

```bash
enclave tui
```

### Flags

| Flag | Effect |
|------|--------|
| `-p, --provider <PROVIDER>` | Provider (`openrouter` · `openai` · `anthropic` · `ollama`) |
| `-m, --model <MODEL>` | Model id |
| `-s, --session <SESSION>` | Open a specific session |
| `--no-keychain` | Do not use the OS keychain for the master key |
| `--no-tools` | No shell-proposal prompts |
| `--no-guard` | Disable the privacy-guard scan (not recommended) |
| `--agent` | Agentic tool loop (read/write/edit files, shell) |
| `--effort <low\|medium\|high>` | Reasoning-effort hint |
| `--auto` | Auto-approve tool calls unless the policy denies them |
| `--plan` | Start in Plan mode (read-only) |
| `--air-gap` | Refuse to send anything to a remote provider |

On launch Enclave **reopens the most recently used session**; the chosen model
and reasoning effort are saved and reused next time.

### Layout

- **Header bar** — app name, active provider/model, mode (plan/build), agent,
  air-gap and route pills; for OpenRouter, account credits.
- **Sessions sidebar** (28 columns, hidden on narrow terminals) — `●` marks the
  active session, `○` the others; `n` new, `r` rename, `d` delete.
- **Transcript** — styled markdown for assistant replies (headings, bold,
  inline code, fenced code windows with a gutter, lists, quotes), inline diffs
  for file edits, and a yellow panel for shell/tool proposals.
- **Right info panel** (shown at ≥ 110 columns) — session name/id, model and
  provider, context estimate (`~N/B tok (P%)`), OpenRouter credits, tools/guard
  state, encrypted DB size, message/session counts, and a **CHANGES** list
  (`+added −removed` per file).
- **Privacy bar** — DB size on disk, session/message counts, cipher, guard
  state and egress count.
- **Footer / inline composer** — the message box with a mode hint; type here.

### Keybindings

| Key | Action |
|-----|--------|
| `Enter` | Send message |
| `Alt+Enter` | New line in the input box (multiline) |
| `Esc` / `Ctrl-C` | Quit |
| `Ctrl-P` | Command palette — pick any `/command` from a searchable list |
| `Ctrl-S` | Session picker overlay (works at any terminal size) |
| `Ctrl-R` | Search text across **all** saved sessions (Enter opens the session) |
| `Ctrl-F` | Find text in the current conversation (Enter copies the line) |
| `Ctrl-Y` | Copy mode: select transcript lines (↑/↓, PgUp/PgDn, Home/End), `y` to copy, `a` all, `e` last reply |
| `Ctrl-O` | Edit the message box in `$EDITOR` (`$VISUAL` → `vi`) |
| `Ctrl-L` | Clear the session (wipes encrypted history, starts fresh) |
| `Ctrl-N` / `Alt+P` | Recall next / previous message from input history |
| `Ctrl-W` / `Ctrl-U` | Delete word / clear input |
| `Tab` | Toggle focus between chat and the sessions sidebar |
| `Shift+Tab` | Toggle Plan / Build mode |
| `PgUp` / `PgDn` (or ↑/↓) | Scroll transcript |
| `?` (empty input) | Toggle the shortcuts overlay |
| Mouse wheel / click | Scroll transcript / open a sidebar session |
| `@file` in the input | Fuzzy file-completion popup (↑/↓ + `Enter`/`Tab` to insert) |
| `n` / `r` / `d` (sidebar or picker) | New / rename / delete session (active one is protected) |
| `y` / `n` / `a` / `q` | Approve / deny / approve-all / skip shell or tool proposals |
| `s` / `p` / `r` / `Esc` (guard overlay) | Send as-is / placeholders / refuse sensitive data |

Keybindings can be overridden in `[tui.keybinds]` (see
[Configuration](#configuration-configtoml)). Recognised actions: `quit`,
`clear`, `copy`, `session_picker`, `toggle_sidebar`, `toggle_mode`, `newline`,
`history_prev`, `history_next`, `delete_word`, `clear_input`, `send`,
`session_search`, `edit_input`. Key specs accept `ctrl`/`alt`/`shift` modifiers
plus key names (`enter`, `esc`, `tab`, `space`, `backspace`, `up`, `down`,
`f1`…`f12`, a single character, …).

### Slash commands

Slash commands are typed in the message box and executed **locally** — they are
never sent to the provider.

| Command | Action |
|---------|--------|
| `/help` | Show the command list |
| `/new` | Create a new session (asks for a name) |
| `/switch` | Open the session picker (aliases `/sessions`, `/resume`, `/continue`) |
| `/branch [name] [--from N]` | Fork the conversation into a new branch |
| `/log` | Show the ASCII branch tree |
| `/checkout <name\|id>` | Open a branch by name or id |
| `/diff <a> <b>` | Line-diff between two sessions |
| `/merge <branch>` | Merge a branch's new turns into this one |
| `/graph` | Navigable branch graph overlay (`/tree`) |
| `/blame <text>` | Which turns/branch introduced some text |
| `/provenance` | What left the machine for this session (`/egress`) |
| `/clear` | Wipe the current session history |
| `/undo` / `/redo` / `/retry` | Remove last turn / restore it / undo-and-resend |
| `/compact` | Summarise the conversation and shrink the history (`/summarize`) |
| `/find <text>` | Search the current conversation (also `Ctrl-F`) |
| `/search <text>` | Search across all saved sessions (also `Ctrl-R`) |
| `/model [id]` | Model picker, or switch directly (`/models` alias) |
| `/effort` | Set reasoning effort: `off` · `low` · `medium` · `high` |
| `/connect [provider]` | Pick / switch the provider (`/provider`, `/providers`) |
| `/thinking` | Toggle reasoning / tool-detail blocks |
| `/details` | Toggle tool-execution details in the transcript |
| `/plan` / `/build` | Switch Plan (read-only) / Build mode |
| `/attach <path>` / `/detach` | Attach a file to the next message / clear attachments |
| `/export [md\|html\|pdf] [path]` | Export the conversation (offline renderers) |
| `/editor` | Edit the message box in `$EDITOR` (also `Ctrl-O`) |
| `/init` | Generate an `AGENTS.md` for this project |
| `/mcp` | List tools exposed by connected MCP servers |
| `/ledger` | Show the encrypted egress ledger |
| `/rag [index <paths>\|search <q>\|status\|clear]` | Local encrypted file index |
| `/airgap [on\|off]` | Toggle air-gap (local only) |
| `/route [on\|off]` | Toggle routing of sensitive turns to Ollama |
| `/remember <text>` | Save a fact to encrypted memory (`--local` keeps it off the network) |
| `/memory [search <q>\|pin <id>]` | List / search / pin memories |
| `/forget <id\|text>` | Delete a memory |
| `/checkpoint` | Summarise this session into long-term memory |
| `/decide <title> [:: rationale]` | Record a decision |
| `/decisions [query]` | List or search decisions |
| `/exposure` | Privacy blast-radius + posture score (`/blast-radius`) |
| `/context` | Show what goes into the context this turn |
| `/theme [name]` | Show / switch the colour theme (or open a picker) |
| `/commands` | List your custom `.md` commands |
| `/credits` | Show OpenRouter credits / usage (`/usage`) |
| `/palette` | Open the command palette (also `Ctrl-P`) |
| `/panic` | Lock now (hide the transcript) |
| `/quit` | Exit Enclave |

Themes: `default` · `nord` · `gruvbox` · `solarized` · `mono`.

### In-chat helpers

- **`@file`** — mention a file by path (`@src/main.rs`, `@README.md`); its
  content is attached locally. If the token is not a real path, Enclave matches
  it against the workspace file list.
- **`!command`** — a message starting with `!` runs as a **local shell command**
  (same sandbox, timeout and output cap as tools) and prints the output. It is
  never forwarded to the model.

---

## Web UI guide

A faithful, interactive web view of the same encrypted vault, styled like the
TUI:

```bash
enclave serve            # binds 127.0.0.1:7878
enclave serve -p 9000    # custom port
```

Enclave prints a one-off URL with a random **per-run token**:

```text
Enclave web UI (local only) → http://127.0.0.1:7878/?token=<token>
Loopback bind, per-run token, embedded assets. Nothing leaves this machine.
Press Ctrl-C to stop.
```

### What it offers

- **Loopback only, token-gated** — every request must carry `?token=<token>` or
  the `x-enclave-token` header. Assets are embedded in the binary; no CDN, zero
  telemetry.
- Same layout as the TUI: header, sessions sidebar, card transcript with
  markdown rendering, right info panel (model, guard, air-gap, DB size, egress,
  tasks), privacy bar and footer.
- **Live chat** over server-sent events; everything is stored in the same
  encrypted vault (SQLCipher).
- **Inline composer** — the message box lives at the end of the transcript
  (no fixed bottom bar); your turns are right-aligned bubbles and the view stays
  pinned to the newest message while replies stream in.
- **Code windows & before/after diffs** — fenced code renders in a framed window
  with line numbers and a copy button; diffs (or tool file edits) render as
  **two panes side by side**, added lines green, removed red.
- **Agentic mode** (`/agent`) — the assistant runs the built-in tools; every
  call appears in a yellow "nothing runs without your approval" panel with
  **Run / Skip** buttons, and edits are summarised in the info panel CHANGES
  list.
- **Attachments** (📎 or `@path`) and local `!command`.
- **Branch graph** — `/graph` (or `Ctrl-G`) renders the conversation tree as an
  SVG; click a node to select, double-click to open, with an action bar
  (open · checkout · merge → current · diff vs current · branch from here ·
  rename · delete). `/diff a b` shows a coloured line diff.
- **Session management** — `+ new`, hover `✎`/`🗑`, or right-click a session for
  Open / Rename / Branch / Delete.
- Theme switcher, model picker + effort picker, provider picker (`/connect`),
  and toggles for plan/build, air-gap, sensitive routing and agent mode.
- Memory (`/memory`, `/remember`, `/forget`), the egress ledger (`/ledger`, with
  chain verification), `/undo` `/redo` `/retry` `/compact`, and export
  (`/export md|html|pdf` — the file downloads from the browser).
- A privacy-guard check before every send, and desktop notifications when a
  reply or tool approval is ready.
- An always-visible **quick-action toolbar** (graph · sessions · model · effort ·
  provider · theme · plan/build · agent · air-gap · route · ledger · memory ·
  rag · find · search · undo · retry · export); active toggles light up.
- **Responsive panels** — the ☰ / ▤ buttons toggle the sessions sidebar and info
  panel (`Alt-S` / `Alt-I`); a "↓ latest" button appears when you scroll up.

### Keyboard shortcuts

| Key | Action |
|-----|--------|
| `Ctrl-P` | Command palette |
| `Ctrl-S` | Session picker |
| `Ctrl-R` | Search across sessions |
| `Ctrl-F` | Find in the conversation |
| `Ctrl-G` | Branch graph |
| `Alt-S` / `Alt-I` | Toggle sessions sidebar / info panel |
| `/` | Slash-command autocomplete |
| `@` | Reference a project file |

### Security model

- The server binds **only** to `127.0.0.1`; there is no remote listener.
- Every request is authenticated with the **per-run random token** (16 random
  bytes, hex-encoded) generated at startup — the token changes each run.
- All assets are embedded in the binary; no external requests are made.

---

## Chat CLI

```bash
enclave chat
```

A line-based REPL over the same encrypted vault. Replies **stream** token by
token. Type `exit`/`quit`/`:q` to leave; `clear` wipes the session.

### Shell proposals (ask-always)

When the assistant emits a fenced ```` ```bash ```` block, Enclave prints the
command and asks before running it:

```text
— the assistant proposed 1 shell command(s); nothing runs without your approval —
$ sw_vers
run? [y]es / [n]o / [a]ll / [q]uit >
```

- Default answer is **no**; there is no auto-run mode.
- Hard timeout (`tools.timeout_secs`, default 30s) and output cap
  (`tools.max_output_bytes`, default 8192 B).
- `--no-tools` disables proposals entirely.
- Output enters the encrypted history and is sent to the provider on the next
  turn — use `--provider ollama` to keep it local.

### Agentic mode

`--agent` switches to real function calling with the built-in tool set
(`read_file`, `write_file`, `edit_file`, `apply_patch`, `list_dir`, `glob`,
`grep`, `run_shell`, `todo`, `question`, plus `remember`, `decide`, `rag_search`
and any MCP tools). Every call is shown and waits for `y`/`n`/`a`/`q`; file
edits return inline diffs.

```bash
enclave chat --agent
enclave chat --agent --auto        # auto-approve unless the policy denies
```

### Attachments, modes and effort

```bash
enclave chat --attach ./diagram.png --attach ./notes.md
enclave chat --plan                # read-only: proposes steps, no mutations
enclave chat --air-gap             # refuse remote providers (use ollama)
enclave chat --effort high         # low | medium | high
```

**Plan vs Build.** *build* (default) has all tools; *plan* refuses mutating
tools and adds a planning note to the system prompt. Switch in the TUI with
`Shift+Tab`, `/plan`, `/build`, or the `--plan` flag.

---

## Privacy features in practice

### Privacy guard decisions

Before any message reaches a **cloud** provider, Enclave scans it for sensitive
data: emails, phone numbers, IBANs, Italian tax IDs, card numbers
(Luhn-validated), API secrets (`sk-…`, `ghp_…`, AWS, JWT…) and IP addresses,
plus offline NER for names, organisations and addresses.

```text
⚠ privacy guard — 2 sensitive item(s) detected:
  · email: <redacted>
  · phone: <redacted>
send [s]as-is / [p]laceholders / [r]efuse >
```

- **as-is** (`s`) — approve this session's content for the network.
- **placeholders** (`p`) — every occurrence becomes a stable token
  (`[EMAIL_1]`, `[IBAN_1]`, …) in **every** outgoing request; the original stays
  only in the encrypted local history.
- **refuse** (`r`, or EOF) — the message is not sent; in the TUI it returns to
  the input box.

`[guard] mode` can be `ask` (default), `redact` (auto-placeholder) or `block`
(auto-refuse). `--no-guard` disables the scan.

### Taint tracking

Any user message in which the guard found sensitive data is persisted as
*tainted*. On every later turn the engine **automatically re-redacts tainted
messages** (stable placeholders, no prompt) before they leave for a remote
provider — regardless of the per-message guard choice. Disable with
`[guard] taint = false`. Local (Ollama) sessions are unaffected.

### Egress policy (policy-as-code)

A declarative `[policy]` forces how each class of sensitive data may leave the
machine: `allow`, `redact` or `block`. Before any request to a remote provider
the engine scans outbound messages and applies the **strictest** matching
action. Local providers are never restricted.

```toml
[policy]
enabled = true
default = "allow"

[policy.rules]
email  = "redact"
phone  = "redact"
iban   = "block"
card   = "block"
secret = "block"
tax_id = "block"
ip     = "allow"
```

Recognised keys: `email`, `phone`, `iban`, `tax_id`, `card`, `secret`, `ip`
(plus `name`, `org`, `address`, `custom` from the NER guard).

### Air-gap

`enclave tui --airgap` / `enclave chat --air-gap`, `air_gap = true` in
`config.toml`, or the `/airgap` toggle makes the engine **refuse to send
anything to a remote provider** — including utility calls (`/compact`,
`/checkpoint`, `/init`). Use a local Ollama provider to keep working.

### Sensitivity routing

With `[routing] sensitive = "local"` (or `/route`), a turn the guard flags as
sensitive is automatically sent to the **local Ollama** provider; non-sensitive
turns keep using the configured provider.

```toml
[routing]
sensitive = "local"   # same (default) | local
```

### Local NER guard

Beyond regex, an **offline** recognizer catches person names, organisations and
postal addresses, plus your own sensitive terms. Placeholders: `[NAME_1]`,
`[ORG_1]`, `[ADDRESS_1]`, `[CUSTOM_1]`.

```toml
[guard]
ner = true
entities = ["Project Phoenix", "Acme S.p.A."]
```

### Local DLP judge

Optionally point `[policy] judge` at a local **Ollama** model: before a payload
leaves for a remote provider, Enclave asks it whether the text still looks
sensitive and applies `judge_action` (`allow`/`redact`/`block`). It runs offline
and fails open.

```toml
[policy]
judge = "llama3.2:1b"
judge_action = "redact"
```

### Inspecting exposure, context and egress

- `/exposure` (alias `/blast-radius`, or `enclave exposure`) — aggregates the
  egress ledger into a blast-radius and a privacy posture score (0–100, grade
  A–F). Counts and kinds only.
- `/context` (or `enclave context`) — the labelled parts of the outgoing
  request, history size, redactions and taint.
- `/ledger` (or `enclave ledger`) — the encrypted, tamper-evident egress ledger
  (SHA-256 fingerprints only). `/ledger --verify` checks the chain;
  `--proof <id>` shows the sent hash, original commitment and redaction map.

---

## Memory & project knowledge

### Long-term memory

A local, encrypted memory of facts and preferences that persists across
sessions and is injected into the system prompt (pinned first, then most recent,
up to `inject_limit`). Nothing goes to an external memory service.

| TUI | CLI |
|-----|-----|
| `/remember <text> #tag` | `enclave memory add "<text>" --tags tag` |
| `/remember <text> --local` | `enclave memory add "<text>" --local-only` |
| `/memory` | `enclave memory list` |
| `/memory search <q>` | `enclave memory search <q>` |
| `/memory pin <id>` | `enclave memory pin <id>` |
| `/forget <id\|text>` | `enclave memory forget <id\|text>` |
| `/checkpoint` | (summarise session into memory) |

```toml
[memory]
enabled = true        # inject memories into the system prompt
inject_limit = 50     # max memories injected
autosave_secs = 0     # >0 = periodically checkpoint the session (opt-in)
```

- **Injection**: the most relevant memories (pinned first, then most recent) are
  added to the system prompt. Injected text is context, so the **privacy guard
  applies** before it reaches a cloud provider.
- **`--local` / `local_only`**: stored but **never injected** into requests that
  leave the machine.
- **Working session**: Enclave reopens the session you were last in
  (`working_session` in `config.toml`, set automatically).

### Project decisions (ADR log)

Record the rationale behind decisions ("why did we choose X?") as an encrypted,
ADR-style log injected into the system prompt like memories.

| TUI | CLI |
|-----|-----|
| `/decide <title> [:: rationale]` | `enclave decisions add "<title>" --body "<rationale>"` |
| `/decisions [query]` | `enclave decisions list` / `enclave decisions search <q>` |
| — | `enclave decisions status <id> <status>` |
| — | `enclave decisions forget <id\|text>` |

In agentic mode the model can record decisions via the `decide` tool
(permission-gated).

---

## Conversation Git

Treat a conversation like git treats code: fork it, explore alternatives in
parallel, compare branches — all stored encrypted in the vault.

| TUI | CLI | What it does |
|-----|-----|--------------|
| `/branch [name]` | `enclave sessions branch --from <id> --name alt --keep 4` | Fork at the current head; parent untouched. Default name `<parent>~N` |
| `/log` | `enclave sessions log` | ASCII branch tree (roots, forks, counts, `●` = current) |
| `/checkout <name\|id>` | — | Open a branch by name or id |
| `/diff <a> <b>` | `enclave sessions diff <a> <b>` | Line-diff between two sessions |
| `/merge <branch>` | `enclave sessions merge <source> --into <target>` | Append a branch's new turns after the common prefix |
| `/graph` | — | Navigable branch graph overlay (↑/↓ select, Enter opens) |
| `/blame <text>` | — | Which turns contain text and whether inherited or introduced |
| `/provenance` | `enclave sessions provenance [id]` | What left the machine for a session (egress ledger) |

Each forked session records its **parent** and **fork point** (`branches`
lineage in `vault.db`), so the tree is reconstructed locally and never leaves
the machine. The fork copies the first `keep` messages (all by default).

```bash
enclave sessions log
enclave sessions branch --from <id> --name alt --keep 4
enclave sessions diff alt main
enclave sessions merge alt --into main
```

---

## Export & search

### Export

```bash
# from the TUI
/export md|html|pdf [path]

# encrypted portable backup (dedicated export password, independent of the master password)
enclave sessions export <id> backup.enclave
enclave sessions import backup.enclave
```

- `/export` renders Markdown, HTML or PDF **natively and offline**; the web UI
  downloads the file straight from the browser.
- `sessions export` writes a `.enclave` file: a JSON payload (name + messages)
  encrypted with AES-256-GCM under a dedicated export password (PBKDF2, fresh
  random salt). Zero plaintext; import recreates the session with a new id.

### Search

| TUI | CLI |
|-----|-----|
| `/find <text>` (or `Ctrl-F`) | — |
| `/search <text>` (or `Ctrl-R`) | `enclave sessions show <id>` |
| `/rag search <q>` | `enclave rag search <q>` |

`/find` searches the current conversation; `/search` and `Ctrl-R` search across
all stored sessions; `rag search` queries the local encrypted file index.

---

## Configuration (`config.toml`)

Configuration lives in the platform config directory (e.g.
`~/.config/enclave/config.toml` on Linux,
`~/Library/Application Support/dev.enclave.enclave/config.toml` on macOS). The
encrypted database (`vault.db`) and salt (`salt.bin`) live alongside it. Run
`enclave config` to see the resolved values (no secrets).

### Top-level keys

| Key | Default | Meaning |
|-----|---------|---------|
| `default_provider` | `"openrouter"` | Provider used when `--provider` is omitted |
| `default_model` | `"mistralai/mistral-large-4-0"` | Model used when `--model` is omitted |
| `use_keychain` | `true` | Cache the derived master key so the password is asked only once |
| `kdf` | `None` | KDF for **new** vaults: `"argon2id"` (default) or `"pbkdf2"` |
| `system_prompt` | `None` | Extra system prompt prepended to every conversation |
| `reasoning_effort` | `None` | `"low"`/`"medium"`/`"high"` hint |
| `ollama_base_url` | `"http://localhost:11434"` | Local Ollama endpoint |
| `working_session` | `None` | Session auto-resumed at startup (set automatically) |
| `air_gap` | `false` | Refuse all remote-provider requests |
| `instructions` | `[]` | Extra local rule files (paths/globs; remote URLs ignored) |

`ENCLAVE_USE_KEYCHAIN=1|0` overrides `use_keychain` for a single run.

### `[tools]`

| Key | Default | Meaning |
|-----|---------|---------|
| `enabled` | `true` | Master switch for proposals/agentic tools |
| `timeout_secs` | `30` | Hard timeout per executed command |
| `max_output_bytes` | `8192` | Per-stream output cap (display + history) |
| `mode` | `"proposals"` | `proposals` (fenced blocks) or `agent` (function calling) |
| `sandbox` | `"auto"` | `auto` · `off` · `fs` · `strict` (macOS `sandbox-exec`) |

### `[guard]`

| Key | Default | Meaning |
|-----|---------|---------|
| `enabled` | `true` | Master switch for the privacy guard |
| `mode` | `"ask"` | `ask` · `redact` · `block` |
| `taint` | `true` | Auto re-redact tainted messages on later turns |
| `injection` | `true` | Prompt-injection hardening + canary token |
| `ner` | `true` | Offline name/org/address detection |
| `entities` | `[]` | Your own sensitive terms |

### `[policy]` — egress policy

| Key | Default | Meaning |
|-----|---------|---------|
| `enabled` | `false` | Enable the policy gate |
| `default` | `"allow"` | Action for kinds without a rule |
| `rules` | `{}` | Per-kind map: `email`, `phone`, `iban`, `tax_id`, `card`, `secret`, `ip` (and `name`, `org`, `address`, `custom`) → `allow`/`redact`/`block` |
| `judge` | `None` | Local Ollama model used as a DLP judge |
| `judge_action` | `"allow"` | `allow` · `redact` · `block` |

### `[routing]`

| Key | Default | Meaning |
|-----|---------|---------|
| `sensitive` | `"same"` | `same` (default) or `local` (route sensitive turns to Ollama) |

### `[network]`

| Key | Default | Meaning |
|-----|---------|---------|
| `proxy` | `None` | `http://`, `https://` or `socks5h://host:port` proxy |
| `tor` | `false` | Route through a local Tor SOCKS proxy (`socks5h://127.0.0.1:9050`) |
| `tls_pin` | `None` | SHA-256 (hex) of the provider leaf certificate |

### `[security]`

| Key | Default | Meaning |
|-----|---------|---------|
| `auto_lock_secs` | `0` | Lock the TUI after inactivity (0 = off) |
| `clipboard_clear_secs` | `30` | Clear Enclave-copied clipboard text after N seconds |
| `duress_password` | `None` | Reserved; prefer `ENCLAVE_DURESS_PASSWORD` (never written to disk) |

### `[memory]`

| Key | Default | Meaning |
|-----|---------|---------|
| `enabled` | `true` | Context injection, `remember` tool, startup reload |
| `autosave_secs` | `0` | Periodic checkpoint interval (0 = off) |
| `inject_limit` | `50` | Max memories injected into the system prompt |

### `[context]`

| Key | Default | Meaning |
|-----|---------|---------|
| `budget_tokens` | `None` | Soft token budget shown in the Context Inspector |
| `warn_pct` | `80` | Warn once the estimate crosses this % of the budget |
| `repomap` | `true` | Inject a compact repository map into the context |

### `[checkpoints]`

| Key | Default | Meaning |
|-----|---------|---------|
| `enabled` | `true` | Take shadow-git workspace snapshots before agentic file edits |
| `max` | `100` | Reserved cap for retained snapshots |

### `[verify]`

| Key | Default | Meaning |
|-----|---------|---------|
| `auto` | `true` | Verify after agentic edits and feed failures back to the model |
| `command` | `None` | Override the auto-detected command (`cargo test`, `npm test`…) |
| `max_attempts` | `2` | How many failing runs are handed back to the model |
| `timeout_secs` | `300` | Timeout for one verification run |

### `[hooks]`

Run a local shell command around every tool call. `pre_tool` blocks the call
when it exits non-zero.

| Key | Default | Meaning |
|-----|---------|---------|
| `pre_tool` | none | Command run before a tool call (non-zero exit blocks it) |
| `post_tool` | none | Command run after a tool call |
| `timeout_secs` | `30` | Timeout for one hook run |

Environment for both hooks: `ENCLAVE_HOOK_EVENT` (`pre`/`post`),
`ENCLAVE_TOOL`, `ENCLAVE_TOOL_ARGS` (raw JSON), `ENCLAVE_WORKSPACE`.

```toml
[hooks]
pre_tool = "echo $ENCLAVE_TOOL >> ~/.enclave-hooks.log"
```

### `[tui]`

| Key | Default | Meaning |
|-----|---------|---------|
| `theme` | `None` | `default` · `nord` · `gruvbox` · `solarized` · `mono` |
| `notify` | `true` | Bell + macOS notification on reply / tool approval |
| `keybinds` | `{}` | Action → key-spec overrides |
| `cursor` | `None` | `block` · `underline` · `line` · `default` |
| `cursor_blinking` | `true` | Whether the input cursor blinks |

```toml
[tui]
theme = "nord"
notify = true

[tui.keybinds]
quit           = "ctrl+q"
copy           = "ctrl+y"
session_picker = "ctrl+s"
toggle_mode    = "ctrl+t"
```

### `[mcp]`

| Key | Default | Meaning |
|-----|---------|---------|
| `allow` | `[]` | Server allowlist (empty = all configured servers) |
| `servers` | `{}` | Map of server name → server config |

Each `[mcp.servers.<name>]` entry: `command` (required), `args`, `env`,
`tools` (tool allowlist; empty = all), `env_allow` (parent env vars to forward;
empty = none).

```toml
[mcp.servers.filesystem]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "~/projects"]
tools = ["read_file", "list_directory"]
env_allow = ["HOME"]
```

### `[agent]` — multi-agent personas

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

The main agent then gets a `delegate(agent, task)` tool. Sub-agent sessions are
ephemeral (RAM-only) and cannot delegate further.

### `[permissions]` — tool policy

| Key | Default | Meaning |
|-----|---------|---------|
| `auto` | `false` | Auto-approve everything that would otherwise `ask` |
| `default` | `None` | Fallback action (`allow`/`ask`/`deny`) |
| `read` / `write` / `edit` / `list` / `glob` / `grep` / `bash` / `delegate` | `None` | Per-tool action |
| `external_directory` | `None` | Any path outside the workspace |
| `doom_loop` | `None` | Same tool call repeating in one turn |
| `bash_rules` | `{}` | Shell-pattern → action (longest match wins) |

```toml
[permissions]
read = "allow"
write = "ask"
bash = "ask"
default = "ask"
external_directory = "ask"

[permissions.bash_rules]
"git status *" = "allow"
"rm *" = "deny"
```

Defaults are read-only friendly: reads are `allow`, mutations
(`write`/`edit`/`bash`/`delegate`) are `ask`, `external_directory` is `ask`.

---

## Common tasks

**Store an API key and start chatting**

```bash
enclave keys set openrouter
enclave chat --provider openrouter --model <model-id>
```

**Keep everything local (no network)**

```bash
ollama pull llama3.2
enclave tui --provider ollama
# or, to be certain:
enclave tui --air-gap --provider ollama
```

**Run the agentic coding loop**

```bash
enclave tui --agent            # ask-always approvals
enclave chat --agent --auto    # auto-approve unless denied by policy
```

**Plan before touching code**

```bash
enclave tui --plan             # or Shift+Tab / /plan inside the TUI
```

**Index your project for local retrieval**

```bash
enclave rag index ./src ./docs
enclave rag search "where is the guard applied"
```

**Remember a preference**

```bash
enclave memory add "always run cargo clippy before committing" --tags workflow
```

**Record a decision**

```bash
enclave decisions add "Use SQLCipher" --body "encrypted at rest, mature" --tags storage
```

**Fork an experiment without losing the main thread**

```bash
enclave sessions branch --from <id> --name experiment --keep 4
enclave tui --session experiment
```

**See what left the machine**

```bash
enclave ledger
enclave ledger --verify
enclave exposure
```

**Back up a conversation**

```bash
enclave sessions export <id> backup.enclave
enclave sessions import backup.enclave
```

**Change the theme or a keybinding**

```bash
# in the TUI: /theme gruvbox
# or edit config.toml:
# [tui]
# theme = "gruvbox"
# [tui.keybinds]
# quit = "ctrl+q"
```

**Start over completely**

```bash
enclave wipe --force    # irreversible: DB + salt + stored keys
```

---

See also: [`README.md`](../README.md) · [`docs/privacy.md`](privacy.md) ·
[`docs/tools.md`](tools.md) · [`docs/providers.md`](providers.md) ·
[`docs/architecture.md`](architecture.md) · [`docs/audit.md`](audit.md).

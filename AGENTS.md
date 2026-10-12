# Enclave — project notes

Privacy-first AI CLI in Rust. Repo: `~/Documents/lavori/Enclave` (v0.1.0, MIT, author Mauro).
Run the built binary from `./dist/enclave`; the user mostly uses `./dist/enclave tui`.

## Build & verify loop (ALWAYS)
After every change:
1. `cargo test` — must stay green (currently 150 tests).
2. `cargo clippy --all-targets` — must be 0 warnings.
3. `cargo build --release`
4. `cp target/release/enclave dist/enclave && codesign --force --sign - dist/enclave`

Step 4 is MANDATORY after every rebuild: the binary is ad-hoc signed, so without re-signing
macOS re-prompts the keychain on launch.

## Git
- Commit ONLY on explicit user request. Do not commit proactively.
- Branch `main`. Last commit at time of writing: `12868cf`
  ("Add Wave 3 features and local Supermemory").
- Working tree (uncommitted): security roadmap Wave A start — A1 Argon2id
  (configurable `kdf` in config, versioned salt file, legacy PBKDF2 still works)
  and A2 protected memory (`src/privacy/secure.rs`: `harden_process`,
  mlock/unlock; `MasterKey` is a locked heap box, zeroized on drop).

## Environment
- Config dir: `~/Library/Application Support/dev.enclave.enclave`
  (`vault.db`, `salt.bin`, `keys.toml`).
- Key resolution: env `ENCLAVE_<PROV>_API_KEY` / `<PROV>_API_KEY` → local `keys.toml`
  (mode 0600) → OS keychain (last resort). Master key cached locally in `keys.toml`
  (`use_keychain` defaults to true).
- Ollama installed and running on `localhost:11434` (no models pulled by default).
- The user has an OpenRouter key (previously 403 "PII detected" — server-side, avoid PII).

## State at 7c03be8
Everything through "Wave 3" is implemented and tested (141 tests green, clippy 0):
crypto/vault/SQLCipher memory, 4 providers (openrouter/openai/anthropic/ollama) with
streaming + real function calling, privacy guard (regex PII + placeholders), encrypted
export/import, shell proposals (ask-always), agentic mode (`--agent`) with builtin tools
(read_file, write_file, edit_file, apply_patch, list_dir, glob, grep, run_shell, todo,
question) + MCP stdio client, Plans/Build modes, permissions (allow/ask/deny, bash_rules,
external_directory, doom_loop, `--auto`), local AGENTS.md rules, custom `.md` commands,
`@file` refs, `!shell`, `/undo /redo /retry /compact`, configurable themes + keybindings,
search (`/find`, `/search`), `/init`, `/export md|html|pdf`, external editor (Ctrl-O),
notifications. TUI is an opencode-style borderless dark layout with a right info panel,
cards transcript and inline diffs.

Docs: `README.md`, `docs/{architecture,privacy,tools,audit,jev-idea,security-roadmap}.md`,
and `docs/Security-Roadmap.pdf` (generated locally with Python + reportlab, since
pandoc/wkhtmltopdf are not installed).

## NEXT WORK (decided with the user)
STATUS: items 1–3 below are now **IMPLEMENTED** (uncommitted; HEAD still `7c03be8`):
local encrypted Supermemory (`/remember /memory /forget /checkpoint` + `enclave memory
add|list|search|pin|edit|forget|clear`, `remember` agent tool, `[memory]` config,
`working_session` resume, periodic autosave). 144 tests green, clippy 0.

The user wants a **local Supermemory built INTO Enclave** (not an external service):
an encrypted, persistent memory of facts/preferences/notes that survives across
sessions and is injected into context — plus the related autoload/checkpoint ideas.

1. **Local Supermemory.** Encrypted `memories` table in `vault.db` (text, tags, kind,
   source session, pinned). Capture manually (`/remember`, `/memory`, `/forget`) and/or
   automatically (summarize a session into memories, opt-in). Inject pinned + recent
   memories into the system prompt (bounded). A `remember` tool lets the agent save
   memories itself (permission-gated). Memories are encrypted at rest; when injected they
   travel to the provider like any context, so the guard applies; allow some memories to
   be local-only. CLI: `enclave memory add|list|search|forget|export`.
2. **Autoload the in-progress session at startup.** On launch, automatically resume the
   session currently "in work" (keep an explicit current/working-session pointer rather
   than just "most recent with messages").
3. **Session-memory checkpoint.** A command that records/saves the session memory either
   on a timer (periodic autosave) or on explicit command (`/checkpoint`).

## Ideas backlog
See `docs/security-roadmap.md` for the privacy/security roadmap. Top picks discussed:
sandbox for approved commands (fs jail + no network), Argon2id + protected memory
(mlock/no-swap), encrypted egress ledger + taint tracking, local encrypted RAG with
per-file ACL. Also: a native Rust PDF renderer so `/export pdf` works without pandoc.

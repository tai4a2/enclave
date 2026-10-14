# Enclave — project notes

Privacy-first AI CLI in Rust. Repo: `~/Documents/lavori/Enclave` (v0.1.0, MIT, author Mauro).
Run the built binary from `./dist/enclave`; the user mostly uses `./dist/enclave tui`.

## Build & verify loop (ALWAYS)
After every change:
1. `cargo test` — must stay green (currently 213 tests).
2. `cargo clippy --all-targets` — must be 0 warnings.
3. `cargo build --release`
4. `cp target/release/enclave dist/enclave && codesign --force --sign - dist/enclave`

Step 4 is MANDATORY after every rebuild: the binary is ad-hoc signed, so without re-signing
macOS re-prompts the keychain on launch.

## Git
- Commit ONLY on explicit user request. Do not commit proactively.
- Branch `main`. Last commit: `fc79301`
  ("Extend Conversation Git: merge, graph view, blame and ledger provenance").

## Environment
- Config dir: `~/Library/Application Support/dev.enclave.enclave`
  (`vault.db`, `salt.bin`, `keys.toml`).
- Key resolution: env `ENCLAVE_<PROV>_API_KEY` / `<PROV>_API_KEY` → local `keys.toml`
  (mode 0600) → OS keychain (last resort). Master key cached locally in `keys.toml`
  (`use_keychain` defaults to true).
- Ollama installed and running on `localhost:11434` (no models pulled by default).
- The user has an OpenRouter key (previously 403 "PII detected" — server-side, avoid PII).
- Toolchain pinned in `rust-toolchain.toml` (1.99.0).

## State (all committed at fc79301)
Everything through security Waves A–C is implemented and tested (213 tests green,
clippy 0): crypto/vault/SQLCipher memory; 4 providers (openrouter/openai/anthropic/ollama)
with streaming + real function calling; privacy guard (regex PII + local NER + placeholders)
with taint tracking, egress policy-as-code, air-gap, prompt-injection canary, sensitivity
routing, DLP local judge; encrypted export/import; shell proposals + agentic mode (`--agent`)
with builtin tools (read_file, write_file, edit_file, apply_patch, list_dir, glob, grep,
run_shell, todo, question, remember, rag_search) + MCP stdio client (hardened); Plan/Build
modes, permissions (allow/ask/deny, bash_rules, external_directory, doom_loop, `--auto`),
local AGENTS.md rules, custom `.md` commands, `@file` refs, `!shell`; `/undo /redo /retry
/compact`, themes + keybindings, `/find`, `/search`, `/init`, `/export md|html|pdf`, external
editor (Ctrl-O), notifications; command sandbox (sandbox-exec); proxy/Tor/TLS pinning;
encrypted egress ledger (`enclave ledger`, `--verify`, `--proof`); local Supermemory
(`enclave memory …`, `/remember /memory /forget /checkpoint`); encrypted local RAG
(`enclave rag index|search|status|clear`, `/rag`, `rag_search` tool); auto-lock/blur/clipboard
TTL; duress + `/panic`. Build/supply-chain: `deny.toml`, `.github/workflows/ci.yml`,
`scripts/release.sh`. TUI is an opencode-style borderless dark layout with right info panel,
cards transcript and inline diffs.

Docs: `README.md`, `docs/{architecture,privacy,tools,audit,jev-idea,security-roadmap}.md`,
and `docs/Security-Roadmap.pdf`.

## NEXT WORK
Security roadmap Waves A–C complete (C2 E2EE sync and C5 split inference are documented
design only). OpenRouter parity, TUI popups (command palette Ctrl-P, provider/theme/model
pickers, `@file` fuzzy completion, slash `/` auto-popup, thinking/details toggles, cursor
style) and the native Rust PDF renderer are all DONE and committed.

### Conversation Git (DONE, committed at 5a6127a + fc79301)
The conversation is treated like git: encrypted, branchable, verifiable.
- Storage: `sessions.branch_parent` + `sessions.branch_from` (migration in
  `src/privacy/memory.rs`); `BranchNode`, `branch_nodes()`, `set_branch()`,
  `list_egress_for_session()`.
- `Session::fork` (copy a prefix into a new branch) and `Session::merge_from`
  (append a branch's new turns after the common prefix).
- TUI: `/branch [name]`, `/log`, `/checkout <name|id>`, `/diff <a> <b>`,
  `/merge <branch>`, `/graph` (`/tree`, navigable colored tree overlay),
  `/blame <text>` (inherited vs introduced), `/provenance` (`/egress`, per-session
  egress ledger entries). Purple-graph overlay: ↑/↓ select, Enter checkout.
- CLI: `enclave sessions branch|log|diff|merge|provenance`.
- Tests: `tests/branch.rs` (9). Docs: README "Conversation branches".

### Ideas still open (not built yet)
- **Privacy Blast-Radius**: live map of every datum (local/remote, provider, when)
  with a "recall" that re-redacts.
- **Local Model Committee**: several local Ollama models debate; a verifier
  cross-checks consensus + dissents.
- Possible extensions of Conversation Git: automatic merge conflict resolution by
  a model, provenance badges inline in the transcript, graph colors per model.

## Ideas backlog
See `docs/security-roadmap.md` for the full privacy/security roadmap. Top remaining picks:
hardware-backed unlock (B10, design only), E2EE sync (C2), split inference (C5).

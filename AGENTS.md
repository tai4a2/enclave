# Enclave — project notes

Privacy-first AI CLI in Rust. Repo: `~/Documents/lavori/Enclave` (v0.1.0, MIT, author Mauro).
Run the built binary from `./dist/enclave`; the user mostly uses `./dist/enclave tui`.

## Build & verify loop (ALWAYS)
After every change:
1. `cargo test` — must stay green (currently 199 tests).
2. `cargo clippy --all-targets` — must be 0 warnings.
3. `cargo build --release`
4. `cp target/release/enclave dist/enclave && codesign --force --sign - dist/enclave`

Step 4 is MANDATORY after every rebuild: the binary is ad-hoc signed, so without re-signing
macOS re-prompts the keychain on launch.

## Git
- Commit ONLY on explicit user request. Do not commit proactively.
- Branch `main`. Last commit at time of writing: `8e0709d`
  ("Add security Waves B–C: sandbox, taint, egress policy, air-gap, injection,
  routing, MCP hardening, NER, Tor/pinning, DLP judge, RAG, proof-of-redaction").

## Environment
- Config dir: `~/Library/Application Support/dev.enclave.enclave`
  (`vault.db`, `salt.bin`, `keys.toml`).
- Key resolution: env `ENCLAVE_<PROV>_API_KEY` / `<PROV>_API_KEY` → local `keys.toml`
  (mode 0600) → OS keychain (last resort). Master key cached locally in `keys.toml`
  (`use_keychain` defaults to true).
- Ollama installed and running on `localhost:11434` (no models pulled by default).
- The user has an OpenRouter key (previously 403 "PII detected" — server-side, avoid PII).
- Toolchain pinned in `rust-toolchain.toml` (1.99.0).

## State (all committed at 8e0709d)
Everything through security Waves A–C is implemented and tested (199 tests green,
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
design only). Open items / ideas:
- OpenRouter feature parity: implement the remaining official API surface as CLI commands
  (generation stats, activity, key management, model endpoints, etc.) and richer TUI pickers.
- [DONE] Native Rust PDF renderer (`src/core/export.rs::render_pdf`) so `/export pdf` works without pandoc/wkhtmltopdf.
- TUI graphic polish toward opencode's latest look (see opencode docs/screenshots).

## Ideas backlog
See `docs/security-roadmap.md` for the full privacy/security roadmap. Top remaining picks:
hardware-backed unlock (B10, design only), E2EE sync (C2), split inference (C5).

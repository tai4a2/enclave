# Changelog

All notable changes to **Enclave** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`enclave guard`** — check text (or a file) for sensitive data offline and
  preview the placeholder form (`enclave guard "…"`, `enclave guard --file log`).
  No provider, no vault, no password.
- **Web UI: guard choice** — the pre-send guard dialog now offers *Cancel* /
  *Use placeholders* / *Send anyway*, shows the placeholder preview, applies
  placeholders automatically in `redact` mode and refuses in `block` mode
  (matching the TUI). `/api/send` and `/api/agent/start` accept `redact: true`.
- **Web UI: full command parity with the TUI** — added the missing slash
  commands and endpoints: `/credits` · `/commands` · `/repomap` · `/skill` ·
  `/attach` `/detach` `/file` · `/copy` · `/save`, plus the TUI aliases
  (`/air-gap`, `/routing`, `/save-point`, `/undo-edit`, `/usage`, `/exit`, `/q`),
  new routes `/api/credits`, `/api/commands`, `/api/repomap`, `/api/skill`, and
  the missing entries in the palette and toolbar. Only `/editor` (`$EDITOR`) and
  `/panic` remain terminal-only.
- **Web UI: brand mark and stable URL** — the logo is inlined as SVG in the
  header and welcome screen and used as the favicon (fully offline). `enclave
  serve` now stores its access token in `web.token` (mode `0600`) so the URL is
  short and stable across launches, and opens the browser automatically
  (`--no-open` to disable).
- **Agent Skills** — local `SKILL.md` instruction packs discovered from
  `.enclave/skills/` and `<config>/skills/`. Only name + description enter the
  context; the body is loaded on demand via the `skill` tool (`/skills`,
  `/skill <name>`, web **skills** button).
- **Repository map** — a compact offline map of the workspace (file → top-level
  symbols, Rust/Python/JS/TS/Go/generic). Injected into the context when
  `[context] repomap = true` and available as the `repo_map` tool (`/repomap`).
- **Tool hooks** — `[hooks] pre_tool` / `post_tool` local commands run around
  every tool call, receiving `ENCLAVE_TOOL` / `ENCLAVE_TOOL_ARGS`; a failing
  `pre_tool` blocks the call.
- **Git worktrees** — `enclave worktree list|add|remove` (TUI `/worktree`,
  web button): one working directory per branch, locally under the app data dir.

- **Workspace checkpoints (snapshot & rewind).** Before every agentic file edit
  Enclave snapshots the working directory into a private *shadow* git repo in the
  app data dir (never the project's `.git`, never the network, neutral `Enclave`
  commit identity). History is linear and reversible: a rewind is itself a new
  snapshot and a safety snapshot is taken first. CLI `enclave checkpoint
  list|create|diff|restore`; TUI `/snapshots`, `/snapshot [label]`,
  `/rewind <id|n>`; web UI **snapshots** toolbar button. Configurable via
  `[checkpoints]` (`enabled`, `max`).

- **Auto verification loop.** After agentic file edits Enclave runs the project's
  own checks locally in the command sandbox (auto-detected: `cargo test`,
  `npm test`, `pytest`, `go test ./...`, `make test`) and hands failures back to
  the model so it fixes them, up to `[verify] max_attempts`. CLI
  `enclave verify [--command <cmd>]`; TUI `/verify`; web UI **verify** button;
  configurable via `[verify]` (`auto`, `command`, `max_attempts`,
  `timeout_secs`).

- **Command risk classifier.** Shell commands are classified offline before they
  run: clearly destructive ones (`rm -rf /`, `dd of=/dev/…`, `mkfs`,
  `curl … | sh`, `shutdown`, fork bombs) are refused by default
  (`[permissions] block_destructive`) and badged in every approval panel; risky
  but recoverable ones (`git push --force`, `git reset --hard`, `sudo`,
  `history -c`) are flagged `⚠ risky`.

## [0.1.0] - 2026-10-10

The first public release of Enclave: a privacy-first AI CLI where encryption is
the main feature, not an afterthought. Zero plaintext at rest, zero telemetry.

### Added

- **Encrypted memory (SQLCipher).** All conversations live in a single
  `vault.db`: AES-256-CBC page encryption with HMAC-SHA512 integrity
  (`cipher_page_size = 4096`, `kdf_iter = 256000`), unlocked with the master key
  using SQLCipher's raw-key syntax.
- **Password-derived master key.** Argon2id (memory-hard, 19 MiB, t=2) by
  default, with legacy PBKDF2-HMAC-SHA256 (600k) vaults still supported (the
  algorithm is recorded in the salt header); a random 32-byte salt; the key is
  zeroized on drop and `mlock`-ed, and core dumps are disabled (`harden_process`).
- **API keys in the OS keychain** (macOS Keychain, Windows Credential Manager,
  Linux Secret Service) with environment-variable override
  (`ENCLAVE_<PROVIDER>_API_KEY` / `<PROVIDER>_API_KEY`) and a local
  `keys.toml` (mode `0600`) cache to avoid repeated keychain prompts.
- **Providers.** OpenRouter, OpenAI, Anthropic and local Ollama, with
  streaming chat and real function calling; provider requests share one hardened
  HTTP client (proxy, Tor SOCKS, TLS certificate pinning).
- **Privacy guard.** Pre-send scanning for emails, phone numbers, IBANs, Italian
  tax IDs, Luhn-validated card numbers, API secrets and IP addresses, with
  as-is / placeholder redaction (`[EMAIL_1]`, …) / refuse, applied consistently
  across the whole history.
- **Local semantic guard (NER).** Offline detection of names, organisations and
  postal addresses, plus a user-defined list of sensitive terms — no model
  download, no network.
- **Taint tracking.** Messages in which the guard found sensitive data are marked
  tainted and automatically re-redacted on every later remote egress.
- **Egress policy-as-code.** Declarative per-kind rules (`allow` / `redact` /
  `block`, strictest match wins) enforced by the engine before any remote send.
- **Air-gap.** A session mode that refuses every remote request outright; local
  (Ollama) providers keep working.
- **Prompt-injection hardening.** Untrusted tool/file output is never treated as
  instructions; a per-run canary token detects echoed system prompts, and tool
  calls following untrusted output always require a fresh approval.
- **Sensitivity routing.** Turns the guard flags as sensitive can be routed
  automatically to the local Ollama provider.
- **Local DLP judge.** An optional local Ollama model acts as a second-line
  filter before remote egress (fails open, runs offline).
- **Command sandbox.** Approved shell commands run inside a macOS `sandbox-exec`
  jail (writes confined to the workspace/temp, optional network block), with an
  ask-always approval model, hard timeout, and output cap.
- **Encrypted egress ledger.** A tamper-evident, hash-chained record of every
  request that leaves the machine — SHA-256 fingerprints, model, timestamp and
  redaction map only, never payloads — with `enclave ledger --verify` and
  **proof-of-redaction** (`enclave ledger --proof <id>`).
- **Agentic mode.** Real function-calling with workspace-confined built-in tools
  (`read_file`, `write_file`, `edit_file`, `apply_patch`, `list_dir`, `glob`,
  `grep`, `run_shell`, `todo`, `question`, `remember`, `decide`, `rag_search`),
  Plan/Build modes, a `[permissions]` model (`allow` / `ask` / `deny`,
  `bash_rules`, `external_directory`, doom-loop gating) and multi-agent
  `delegate` with per-persona sub-agents.
- **opencode-style TUI.** Full-screen interface with a sessions sidebar, live
  info panel, markdown rendering, inline diffs, streaming spinner, command
  palette, session picker, fuzzy `@file` completion, themes and configurable
  keybindings.
- **Local web UI** (`enclave serve`). A loopback-only, per-run-token-gated view
  of the same encrypted memory: live streaming chat, agentic tools, branch graph
  (SVG), memory, ledger and export.
- **Conversation Git.** Encrypted conversation branches — fork (`/branch`),
  tree (`/log`), checkout, `diff`, `merge`, navigable `/graph`, `/blame` and
  per-session `/provenance`.
- **Project decisions (ADR log).** Encrypted, searchable decision records with
  rationale, injected into the system prompt and settable via the `decide` tool.
- **Context inspector and budgeter.** `enclave context` breaks the outgoing
  request into labelled parts (prompt, rules, plan, memory, decisions,
  anti-injection notice) with sizes; `[context] budget_tokens` adds a live token
  usage bar.
- **Privacy exposure.** `enclave exposure` aggregates the egress ledger into a
  blast-radius report and a privacy posture score (0–100, grade A–F).
- **Local RAG.** `enclave rag index|search|status|clear` — an encrypted,
  fully-offline BM25-style file index with a per-file ACL re-checked at query
  time.
- **MCP support.** A minimal stdio Model Context Protocol client with hardened
  defaults (server/tool allowlists, cleared child environment, optional sandbox).
- **Encrypted export/import.** Portable `.enclave` session backups encrypted
  with AES-256-GCM under a dedicated password (fresh salt per export), plus
  native offline `md` / `html` / `pdf` export.
- **Attachments.** Images (multimodal) and text files stored encrypted in the
  vault; text attachments are inlined and scanned by the privacy guard.
- **Long-term memory.** A local, encrypted store of facts and preferences that
  is injected into the system prompt and can be pinned or marked `local_only`.
- **Security UX.** Auto-lock on inactivity, blur-on-unfocus, clipboard
  auto-clear, `/panic` instant lock, and an optional duress password that opens
  a separate decoy vault.
- **Supply chain tooling.** `deny.toml` (permissive licenses, no wildcards,
  crates.io only), a CI workflow (fmt, clippy, tests, `cargo-audit`,
  `cargo-deny`, CycloneDX SBOM) and a reproducible signed release script
  (`scripts/release.sh`) with SHA-256 and SBOM artifacts.

### Changed

- Master-key derivation moved to Argon2id for new vaults while keeping PBKDF2
  for backward compatibility (the algorithm is recorded in the salt header).
- API keys are read lazily on first use, and the OS keychain is a fallback
  behind environment variables and the local `keys.toml`, so macOS does not
  prompt on every launch.
- Provider traffic is routed through a single shared HTTP client so proxy, Tor
  and TLS-pinning settings apply uniformly.
- Deleted ciphertext is reclaimed from the database file with `VACUUM`
  (`sessions delete --purge`, `sessions wipe-all`, `sessions vacuum`).
- TUI styling was reworked into an opencode-style layout with framed code
  windows and coloured inline diffs; conversation branches were extended with
  merge, graph view, blame and ledger provenance.

### Fixed

- **Keychain cache now verifies the typed password.** The cached key is accepted
  only if the typed password derives exactly the same key (constant-time
  comparison); a wrong password returns `auth error: wrong master password`.
- Deleted session ciphertext no longer lingers on disk as freed pages after
  `--purge` / `wipe-all` / `vacuum`.
- UTF-8 truncation of large command output is now boundary-safe.

### Security

- Closed a keychain-cache bypass and documented the residual risks of shell
  tools, remote-provider transit, and in-RAM plaintext in
  [docs/privacy.md](docs/privacy.md) and [docs/audit.md](docs/audit.md).
- Added prompt-injection defenses (untrusted-output handling, canary token,
  fresh-approval downgrade) and a command sandbox for approved shell commands.
- Added `cargo-audit` (RUSTSEC) and `cargo-deny` to CI, plus a CycloneDX SBOM
  step, for supply-chain visibility.

[Unreleased]: https://github.com/tai4a2/enclave/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tai4a2/enclave/releases/tag/v0.1.0

# Enclave — project notes

Privacy-first AI CLI in Rust. Repo: `~/Documents/lavori/Enclave` (v0.1.0, MIT, author tai4a2).
Run the built binary from `./dist/enclave`; the user mostly uses `./dist/enclave tui`.

## Build & verify loop (ALWAYS)
After every change:
1. `cargo test` — must stay green (currently 243 tests).
2. `cargo clippy --all-targets` — must be 0 warnings.
3. `cargo build --release`
4. `cp target/release/enclave dist/enclave && codesign --force --sign - dist/enclave`

Step 4 is MANDATORY after every rebuild: the binary is ad-hoc signed, so without re-signing
macOS re-prompts the keychain on launch.

## Git
- Commit ONLY on explicit user request. Do not commit proactively.
- Branch `main`. Remote `origin` = <https://github.com/tai4a2/enclave> (public, MIT).
- Identity for this repo: `tai4a2 <tai4a2@users.noreply.github.com>`.
  NOTE: on 2026-10-20 the whole history was rewritten with `git filter-branch` to strip the
  personal e-mail from every commit — commit hashes recorded before that date are INVALID.
- Last commit: see `git log --oneline -1` (do not hard-code a hash here — history is rewritten
  periodically to keep the tree clean).

## Environment
- Config dir: `~/Library/Application Support/dev.enclave.enclave`
  (`vault.db`, `salt.bin`, `keys.toml`).
- Key resolution: env `ENCLAVE_<PROV>_API_KEY` / `<PROV>_API_KEY` → local `keys.toml`
  (mode 0600) → OS keychain (last resort). Master key cached locally in `keys.toml`
  (`use_keychain` defaults to true).
- Ollama installed and running on `localhost:11434` (no models pulled by default).
- The user has an OpenRouter key (previously 403 "PII detected" — server-side, avoid PII).
- Toolchain pinned in `rust-toolchain.toml` (1.99.0).

## State (HEAD d971408; 243 tests green, clippy 0)
Everything through security Waves A–C is implemented and tested (218 tests green,
clippy 0): crypto/vault/SQLCipher memory; 4 providers (openrouter/openai/anthropic/ollama)
with streaming + real function calling; privacy guard (regex PII + local NER + placeholders)
with taint tracking, egress policy-as-code, air-gap, prompt-injection canary, sensitivity
routing, DLP local judge; encrypted export/import; shell proposals + agentic mode (`--agent`)
with builtin tools (read_file, write_file, edit_file, apply_patch, list_dir, glob, grep,
run_shell, todo, question, remember, decide, rag_search) + MCP stdio client (hardened); Plan/Build
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

Also done and committed at `9c77225`: the **web UI chat redesign** (inline composer at the
end of the transcript, right-aligned user bubbles, framed code windows with line numbers +
copy, before/after split diffs) and the **TUI code windows** (`╭─`/`╰─` framed blocks with
coloured diff lines); supply-chain fixes (rustls 0.23.46, ratatui 0.30 `default-features=false`
+ `crossterm`, `deny.toml` + `CDLA-Permissive-2.0`); `cargo fmt` across the tree; `keys.toml`
added to `.gitignore`.

Docs: `README.md` (banner, badges, screenshots, quickstart), `docs/{INSTALL,USAGE,architecture,
privacy,tools,providers,audit,jev-idea,security-roadmap,roadmap-memory-context}.md`, root
`SECURITY.md` / `CONTRIBUTING.md` / `CODE_OF_CONDUCT.md` / `CHANGELOG.md`, `assets/` (logo,
banner, tui.png, web.png), `scripts/install.sh`. Tests: 243. Linux CI simulated green
(fmt/clippy/test/deny/audit) via a Docker container `enclave-linux`.

## Publishing status (PUBLIC at github.com/tai4a2/enclave)
- Repo: <https://github.com/tai4a2/enclave> (public, MIT). `Cargo.toml` `repository` points there,
  and the OpenRouter `HTTP-Referer` header uses the same URL.
- Release `v0.1.0`: tag + GitHub Release carrying the ad-hoc-signed macOS binary,
  `enclave.sha256` and the CycloneDX SBOM (`scripts/release.sh` produces them).
- CI: `.github/workflows/ci.yml` (fmt, `clippy --all-targets -- -D warnings`, tests,
  `cargo-audit`, `cargo-deny`, CycloneDX SBOM), triggered on push to `main` and tags `v*`.
- Private vulnerability reporting enabled on the repo (see `SECURITY.md`).
- Privacy: no real secrets in the tree (token-like strings are test fixtures) and the personal
  e-mail was stripped from the whole history (see the Git section above).
- Windows support was explicitly NOT pursued (macOS + Linux only). The shell invocation is
  hard-wired to `sh -c` (`src/core/tools.rs`), so Windows would need a `cmd /C` branch; the
  sandbox and `secure.rs` (mlock) are macOS/unix-only.

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

### Project memory & privacy posture (DONE; committed at 9205be5 + uncommitted Context Inspector/budgeter)
- **Context budgeter** (#9, new, UNCOMMITTED): `[context] budget_tokens` + `warn_pct`
  (`ContextSettings` in `src/config.rs`); `ChatEngine.context_budget`/`context_warn_pct`;
  `ContextReport.est_tokens`/`limit_tokens`/`warn_pct` (+ `estimate_tokens`, chars/4);
  CLI `context_cmd` prints `~N tokens · budget X (P%) [####------]` + a ⚠ warning past
  warn_pct; TUI info-panel `context` row shows `~N/B tok (P%)` coloured yellow/red;
  web `/api/context` + `openContext()` show the bar. v1 (no per-source quota yet).
- **Context Inspector** (#16): `ChatEngine::system_parts()` + `context_report()`
  (`ContextReport`/`ContextPart` in `src/core/engine.rs`) break the outgoing request
  into labelled parts (prompt, rules, plan, memory, decisions, anti-injection) with
  preview + size, plus history/redactions/taint. CLI `enclave context [--session]`,
  TUI `/context`, web `/api/context` + overlay + toolbar chip.
- **Decision Log / ADR** (#2): encrypted `decisions` table in `src/privacy/memory.rs`
  (`Decision`, `add_decision`, `list_decisions`, `search_decisions`, `set_decision_status`,
  `delete_decision`, `delete_decisions_matching`, `decision_count`); injected into the
  system prompt; `decide` agent tool; TUI `/decide` `/decisions`; CLI `enclave decisions
  list|add|search|status|forget`; web UI `/api/decisions`.
- **Privacy Blast-Radius** (#20) + **Privacy score** (#26d): `src/privacy/exposure.rs`
  (`blast_radius`, `privacy_score`, `BlastRadius`, `PrivacyScore`, `ScoreInputs`) over
  `EgressSummary` (`EncryptedMemory::egress_summary`); CLI `enclave exposure [--session]`;
  TUI `/exposure` (`/blast-radius`); web UI `/api/exposure` + toolbar button. Counts/kinds
  only, never payloads.

### Workspace checkpoints (NEW, UNCOMMITTED)
Snapshot & rewind for agent file edits, in a private *shadow* git repo (`<data>/checkpoints.git`,
never the project's `.git`, no network, neutral `Enclave` commit identity).
- Core: `src/core/checkpoint.rs` (`CheckpointStore::{new,is_available,snapshot,list,count,restore,diff_stat}`;
  `restore` = checkout `<id> -- .` + `clean -fd` + a new `rewind to <id>` snapshot → history stays
  linear/reversible). `Checkpoint` struct. Exported from `src/core/mod.rs`.
- Config `[checkpoints]` (`CheckpointSettings{enabled=true,max=100}` in `src/config.rs`).
- Engine: `ChatEngine.checkpoints: Option<CheckpointStore>`, `snapshot(label)`, `checkpoint_before(call)`
  (auto-snapshot before mutating tools; `is_mutating_tool` now also covers `apply_patch`); wired in
  `build_engine` so CLI/TUI/web all get it.
- CLI: `enclave checkpoint list|create|diff|restore` (`Command::Checkpoint`/`CheckpointAction`, `checkpoint_cmd`).
- TUI: `/snapshots` (`/ckpt`), `/snapshot [label]`, `/rewind <id|n>`.
- Web: `/api/checkpoints[/save|/restore]` + `openCkpt/saveCkpt/restoreCkpt` + toolbar **snapshots** chip.
- Tests: `tests/checkpoint.rs` (3). Docs: README + docs/USAGE.md + CHANGELOG.
Wave 2 next: auto verify loop after edits + LSP diagnostics + command risk classifier.
Wave 3: Agent Skills + repo map/code index + hooks + git worktree per branch.

### Wave 2 — risk classifier, auto-verify, traffic menu (NEW, UNCOMMITTED)
- **Command risk classifier** `src/core/risk.rs` (`Risk{High,Medium}`, `RiskHit`,
  `classify(cmd)`): offline heuristics for `rm -rf /|~|*`, `dd of=/dev/`,
  `mkfs`, fork bomb, `> /dev/sd*`, `shutdown/reboot`, `sudo rm`, `curl|sh`,
  `eval$(curl` (High) and `git push --force`, `git reset --hard`,
  `git clean -fd`, `sudo`, `chmod -R 777 /`, `npm/cargo publish`, `history -c`
  (Medium). Wired in `ChatEngine::effective_action` (High → `Deny` when
  `[permissions] block_destructive` (default true), else always `Ask`) and
  exposed via `ChatEngine::risk_of` for badges (CLI `CliGate`, TUI ToolConfirm
  panel, web approval panel `risk` field).
- **Auto verification loop** `src/core/verify.rs` (`VerifyCommand`,
  `VerifyReport`, `detect(ws)`, `run(...)`, `feedback(...)`): detects
  `cargo test --quiet` / `npm|pnpm|yarn test` / `pytest -q` / `go test ./...` /
  `make test`; `ChatEngine.verify_auto|verify_command|verify_max_attempts|
  verify_timeout_secs` + `verify_program()` + `run_verification(&mut self, ctx)`;
  `turn_agentic_with` counts mutating edits and, on the final text, runs the
  checks and feeds failures back as a user message (loop, bounded by
  `max_attempts`). Config `[verify]` (`auto=true`, `command`, `max_attempts=2`,
  `timeout_secs=300`). CLI `enclave verify [--command <cmd>] [--no-sandbox]`
  (`verify_cmd`, exit 1 on failure); TUI `/verify`; web `POST /api/verify` +
  **verify** button.
- **Traffic menu** (what left the machine + what was intercepted): TUI `/traffic`
  (`/sent`) via `traffic_text()`; web `openTraffic()` overlay + **traffic**
  toolbar chip (from `/api/ledger`, flags entries with non-empty `redactions`).
- Sandbox gained toolchain-cache write dirs (`CARGO_HOME`/`RUSTUP_HOME`/`GOPATH`/
  `GOCACHE`/`GOMODCACHE` + `~/.cargo`, `~/.rustup`, `~/.npm`, `~/.cache`, `~/go`)
  so `cargo test` etc. work inside the fs jail.
- Tests 224 → 232 (risk 3, verify 5). Docs: README (Verify loop + risk classifier
  sections, `enclave verify` row), docs/USAGE.md (`verify` section + `[verify]`
  table), CHANGELOG `[Unreleased]`.
### Wave 3 — Agent Skills, repo map, hooks, worktrees (NEW, UNCOMMITTED)
- **`src/core/skills.rs`**: `SKILL.md` discovery from
  `<workspace>/.enclave/skills/<name>/` (or `<name>.md`) + `<config>/skills/`
  (project overrides global); `parse()` (front-matter name/description),
  `load_all()`, `SkillsRegistry{get,names,entries,index_text}`. Only the
  name+description list enters the prompt; the body loads on demand.
- **`src/core/repomap.rs`**: `symbols_for()` (Rust/Python/JS/TS/Go/generic
  regexes), `build(workspace,max_files,max_chars)`, `filter()`, `RepoMap`.
- **`src/core/hooks.rs`**: `HooksSettings` (`[hooks] pre_tool`/`post_tool`/
  `timeout_secs`), `Hooks`, `run_hook()` (env `ENCLAVE_HOOK_EVENT`,
  `ENCLAVE_TOOL`, `ENCLAVE_TOOL_ARGS`, `ENCLAVE_WORKSPACE`; non-zero exit
  blocks). Wired in `builtin_tools::execute_detailed` (pre→inner→post) so every
  execution path gets hooks; `ToolContext.hooks`.
- **`src/core/worktree.rs`**: `is_repo`, `list` (porcelain), `add`, `remove`,
  `default_dir(data_dir,name)`; CLI `Command::Worktree` +
  `WorktreeAction{List,Add{name,base,path},Remove{name,force}}` + `worktree_cmd`.
- Engine: `ChatEngine` gained `skills: Option<Arc<SkillsRegistry>>`, `hooks:
  Option<Hooks>`, `repo_map: Option<String>`; `system_parts()` adds "skills" and
  "repo map" parts. `builtin_tools::defs()` grew to 15 base tools (added `skill`
  and `repo_map`; delegate now index 15 / 16 total).
- CLI `build_engine` loads skills, hooks and the repo map (when
  `[context] repomap = true`).
- TUI slash: `/skills`, `/skill <name>`, `/repomap`,
  `/worktree [list|new|use|remove]`; web: **skills** + **worktree** toolbar
  chips, `openSkills()`/`openWorktree()`, `/api/worktree` (op list|add|remove),
  `state_json` gained `skills`, `hooks`, `repomap`.
- Tests: 232 → 243 (skills 3, repomap 3, hooks 2, worktree 1, memory +1).
  Docs: README (Agent Skills / Repository map / Tool hooks / Git worktrees
  sections + `enclave worktree` row), docs/USAGE.md (`worktree` + skills/repo
  map sections, `[hooks]` table, `[context] repomap` row), CHANGELOG
  `[Unreleased]`.

### Ideas still open (not built yet)
- **Local Model Committee**: several local Ollama models debate; a verifier
  cross-checks consensus + dissents.
- Possible extensions of Conversation Git: automatic merge conflict resolution by
  a model, provenance badges inline in the transcript, graph colors per model.
- See `docs/roadmap-memory-context.md` for the full 27-idea scored roadmap.

## Ideas backlog
See `docs/security-roadmap.md` for the full privacy/security roadmap. Top remaining picks:
hardware-backed unlock (B10, design only), E2EE sync (C2), split inference (C5).

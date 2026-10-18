# Contributing to Enclave

Thanks for wanting to help! Enclave is a privacy-first AI CLI written in Rust,
and contributions of all kinds are welcome — bug reports, docs, tests, and code.

By participating you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md).
For security issues, **do not open a public issue** — see [SECURITY.md](SECURITY.md).

## Development environment

The toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml)
(currently Rust `1.99.0` with `rustfmt` and `clippy`). With
[rustup](https://rustup.rs) installed, the right toolchain is selected
automatically when you work in the repository — you do not need to install it
manually.

```bash
# Debug build
cargo build

# Run the full-screen TUI
./target/debug/enclave tui

# Run the local web UI (loopback only, prints a one-off token URL)
./target/debug/enclave serve -p 7878

# Plain CLI chat
./target/debug/enclave chat --provider ollama --model llama3.2
```

See the [README](README.md) for the full command surface. A local
[Ollama](https://ollama.com) instance (`localhost:11434`) lets you exercise the
whole app offline, with no API keys and nothing leaving your machine — the
easiest way to test changes.

## Required local checks

Every pull request must pass the same checks CI runs. Run them before pushing:

```bash
cargo fmt --all                                        # format
cargo clippy --all-targets -- -D warnings              # lints, warnings are errors
cargo test                                             # unit + integration tests
```

Optional but recommended (matches the supply-chain jobs in CI):

```bash
cargo audit            # RUSTSEC advisories
cargo deny check       # licenses, bans, sources (config in deny.toml)
```

CI (`.github/workflows/ci.yml`) runs `cargo fmt --all -- --check`,
`cargo clippy --all-targets -- -D warnings`, `cargo test --all-targets`,
`cargo-audit`, `cargo-deny` and produces a CycloneDX SBOM. A review cannot start
until it is green.

## Coding style and conventions

- **Match the surrounding code.** Read the neighbouring module first and mirror
  its structure, naming and error handling.
- Run `rustfmt` (there is no custom `rustfmt.toml`, so defaults apply) — do not
  hand-format.
- Keep `clippy` at **zero warnings**; do not add `#[allow(...)]` to silence a
  lint without a good reason in a comment.
- Errors use this crate's `Result` / `EnclaveError` (`src/error.rs`) — prefer
  `?` and the existing error constructors over `unwrap`/`expect` in library code.
- **Do not add comments unless they add real information.** The existing code is
  documented with short, purposeful comments; avoid noise.
- Any behaviour change should come with tests. Integration tests live in
  `tests/`; unit tests live next to the code in `#[cfg(test)] mod tests`.
- Security-relevant code (crypto, guard, policy, sandbox, egress) should
  document the property it enforces and, where possible, assert it in a test.

### Commit messages

Concise and **imperative**, like the existing history:

```text
Add context budgeter (soft token budget with live usage bar)
Fix keychain cache to verify the typed password
```

- One logical change per commit.
- Start with a capitalised verb (`Add`, `Fix`, `Remove`, `Refactor`, `Document`).
- Keep the subject under ~72 characters; add a body only when the "why" is not
  obvious.

## Adding a feature

### A new provider

Providers implement the `Provider` trait in
[`src/providers/mod.rs`](src/providers/mod.rs). The moving parts:

1. Create `src/providers/<name>.rs` implementing `Provider` (`name`,
   `default_model`, `chat_stream`, and `chat_with_tools` if the API supports
   function calling). For OpenAI-compatible APIs, reuse the shared helpers in
   [`src/providers/openai_compat.rs`](src/providers/openai_compat.rs), and route
   HTTP through the shared client in [`src/providers/http.rs`](src/providers/http.rs)
   so proxy/Tor/TLS-pinning settings apply.
2. Add the module and `pub use` in `src/providers/mod.rs`.
3. Register the name in `known_providers()`, `requires_api_key()`,
   `default_model_for()`, `suggested_models()` and the `create_provider()`
   match arm in the same file.
4. Make sure API-key resolution still works (the key is looked up from
   `ENCLAVE_<PROVIDER>_API_KEY` / `<PROVIDER>_API_KEY`, then the local
   `keys.toml`, then the OS keychain).
5. Add a test using `MockProvider` or a focused unit test for the request/stream
   (and to the byte-level parsing).

### A new built-in tool

Built-in agent tools live in
[`src/core/builtin_tools.rs`](src/core/builtin_tools.rs):

1. Add a `ToolDef::new(...)` entry (name, description, JSON-Schema `parameters`)
   to `defs()`.
2. Handle the call by adding a match arm to `execute_detailed()`. Return a
   `ToolOutcome` (rendered text plus an optional `FileChange` for the UI's
   CHANGES list).
3. Confine file paths to the workspace with `resolve_in_workspace()`; never
   bypass the sandbox for `run_shell`.
4. Ensure the new tool has a sensible default in the permission model
   ([`src/core/permissions.rs`](src/core/permissions.rs)) — default to `ask` for
   anything that mutates state or touches the network.
5. Add tests (the module already has `AllowAll` helpers you can reuse).

### A new slash command

Slash commands are local actions — they are executed by the client and **never
sent to the provider**. In the TUI
([`src/tui/app.rs`](src/tui/app.rs)):

1. Add the handler in the `match cmd { ... }` block where user input starting
   with `/` is dispatched.
2. Register it in the `PALETTE_COMMANDS` list (Ctrl-P palette and `/`-autopopup)
   and update the `SLASH_HELP` string.
3. Mirror the command in the web UI (`src/web.rs`) if it makes sense there.

For user-authored commands that do not belong in the binary, note that users can
drop Markdown files in `.enclave/commands/` or `<config_dir>/commands/` — see
`src/core/commands.rs` for the front-matter format.

## Branch and pull request workflow

1. Fork the repository and create a topic branch off `main`, e.g.
   `git checkout -b feat/context-budgeter`.
2. Make your change in small, focused commits (see the commit style above).
3. Run the [required checks](#required-local-checks) and make sure they pass.
4. Open a pull request against `main` with a clear description: what changed,
   why, and how you tested it. Link any related issue.
5. Keep the PR focused; split unrelated changes into separate PRs.
6. Be responsive to review feedback. Maintainers may squash-merge.

## What not to commit

The `.gitignore` already excludes most of these, but double-check your diff:

- **Secrets and API keys** of any kind, and your `keys.toml`.
- **`vault.db`**, `salt.bin`, and any other encrypted database or salt file
  (`*.db`, `*.db-journal`).
- **`dist/`** — the built/signed binary and its SHA-256/`SBOM` artifacts.
- `target/` build output, `.env` files, and editor/OS cruft.

If you accidentally commit a secret, rotate it immediately and tell the
maintainers — do not just delete the commit.

## Manual testing the local web UI

`enclave serve` starts the local-only web UI (loopback only, token-gated on
every request):

```bash
cargo run -- serve -p 7878
# or, using a release build:
./dist/enclave serve            # binds 127.0.0.1:7878
```

It prints a one-off URL with a random per-run token, e.g.
`http://127.0.0.1:7878/?token=<token>` — open it in a browser. Try the chat,
the toolbar toggles (agent, air-gap, routing), the branch graph, memory, the
egress ledger and an export. Everything is stored in the same encrypted vault as
the TUI, so you can create a throwaway session and delete it afterwards.

# Enclave v0.1.0

**Privacy-first AI coding assistant — encrypted by design.** MIT · macOS + Linux · Rust.

Enclave is a local-first AI CLI (TUI + web UI) whose memory is encrypted at rest and whose
data flow you can inspect, restrict and prove. No telemetry, no cloud sync, no plaintext
history.

## Highlights

- **Encrypted memory** — every conversation lives in a single `vault.db`
  (SQLCipher, AES-256 with HMAC-SHA512 integrity). The master key is derived with
  **Argon2id**, zeroized on drop, `mlock`-ed (never swapped) and core dumps are disabled.
- **Privacy guard** — every outbound message is scanned for emails, phones, IBANs, Italian
  tax IDs, Luhn-validated cards, API secrets and IP addresses, plus an offline **NER** pass
  for names / organisations / addresses. Choose *send as-is*, *placeholders*
  (`[EMAIL_1] …`) or *refuse* — or make it automatic.
- **Taint tracking** — once a message is flagged sensitive, it is re-redacted on every later
  remote egress, automatically.
- **Egress policy-as-code** — declarative `allow` / `redact` / `block` rules per data kind,
  enforced before any remote request; local Ollama is exempt.
- **Air-gap** — a session mode that refuses every remote call outright.
- **Encrypted egress ledger** — a tamper-evident, hash-chained record of what left the
  machine (SHA-256 fingerprints, model, timestamp, redaction map only), with
  `enclave ledger --verify` and **proof-of-redaction**.
- **Privacy exposure** — `enclave exposure` turns that ledger into a blast-radius report and
  a 0–100 privacy score with per-factor explanation.
- **Prompt-injection hardening** and a **command sandbox** (`sandbox-exec`) for approved
  shell commands, with a risk classifier that refuses destructive commands by default.
- **4 providers** (OpenRouter, OpenAI, Anthropic, local **Ollama**) with streaming chat and
  real **function calling**; hardened MCP stdio client.
- **Agentic mode** — workspace-confined tools (`read_file`, `write_file`, `edit_file`,
  `apply_patch`, `list_dir`, `glob`, `grep`, `run_shell`, `todo`, `question`, `remember`,
  `decide`, `rag_search`), Plan/Build modes, a full permission model, multi-agent `delegate`.
- **opencode-style TUI** and a **local web UI** (`enclave serve`, loopback + token, opens
  the browser) sharing the same encrypted vault.
- **Conversation Git** — encrypted conversation branches with `branch`, `log`, `graph`,
  `checkout`, `diff`, `merge`, `blame`, `provenance`.
- **Project memory** — decision log (ADR), long-term memories, context inspector and token
  budgeter, local encrypted **RAG** index.
- **Workspace checkpoints & rewind**, **auto-verify loop**, **traffic view**, **Agent
  Skills**, **repository map**, **tool hooks**, **git worktrees**.
- **Supply chain** — `cargo-audit` + `cargo-deny` + CycloneDX SBOM in CI (green), pinned
  toolchain, signed release script.

## Install

### From source (recommended)

```bash
git clone https://github.com/tai4a2/enclave.git
cd enclave
cargo build --release
./target/release/enclave tui
```

Requirements: Rust (pinned via `rust-toolchain.toml`). On Linux you also need the build
dependencies:

```bash
# Debian / Ubuntu
sudo apt-get install -y build-essential pkg-config libdbus-1-dev
# Fedora / RHEL
sudo dnf install gcc make pkgconf-pkg-config dbus-devel
# Arch
sudo pacman -S base-devel pkgconf dbus
```

Or install into `~/.cargo/bin` with `cargo install --path .`, or run `./scripts/install.sh`.

### Prebuilt macOS binary (attached below)

`enclave` is an ad-hoc-signed **macOS arm64 (Apple Silicon)** build, produced by
`scripts/release.sh`. Because it is not notarized, macOS will quarantine it; clear the flag
once:

```bash
chmod +x enclave
xattr -d com.apple.quarantine enclave 2>/dev/null || true
./enclave tui
```

## Verify the download

```bash
shasum -a 256 enclave        # macOS   (sha256sum on Linux)
# must match the value in enclave.sha256
```

This build:

```
f19d9a72a4e2b662bf275e5255e285e67b863b05a2026c82cee4ab2291ecafb7  enclave   (15248848 bytes)
```

## First run

1. Enclave asks for a **master password** and creates your encrypted vault
   (`vault.db` + `salt.bin`) in your own config dir — `~/Library/Application Support/dev.enclave.enclave`
   on macOS. **It is not recoverable: write it down.**
2. Add a provider key: `enclave keys set openrouter` (stored locally in `keys.toml`, mode
   0600) or `export ENCLAVE_OPENROUTER_API_KEY=…`.
3. Or stay fully local: `ollama pull llama3.1` then `enclave tui --provider ollama`.
4. Web UI: `enclave serve` (loopback only, opens your browser).
5. `enclave --help` and `docs/USAGE.md` cover everything else.

## Documentation

- [README](https://github.com/tai4a2/enclave#readme)
- [Install guide](https://github.com/tai4a2/enclave/blob/main/docs/INSTALL.md)
- [User manual](https://github.com/tai4a2/enclave/blob/main/docs/USAGE.md)
- [Privacy model](https://github.com/tai4a2/enclave/blob/main/docs/privacy.md)
- [Architecture](https://github.com/tai4a2/enclave/blob/main/docs/architecture.md)
- [Security policy](https://github.com/tai4a2/enclave/blob/main/SECURITY.md)

## Notes

- Windows is not supported (the shell tool, sandbox and memory locking are unix-only).
- This is `0.1.0`: the crypto, guard, ledger and CI are tested (243 tests), but interfaces
  may still change before `1.0`.
- Security reports: please use GitHub private vulnerability reporting (see `SECURITY.md`).

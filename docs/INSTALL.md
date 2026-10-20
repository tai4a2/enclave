# Installing Enclave

A privacy-first AI coding CLI with encrypted local memory, built in Rust — how to build, install, and set it up.

## Requirements

- **Rust toolchain** — the version is pinned in [`rust-toolchain.toml`](../rust-toolchain.toml) (`1.99.0`, with `rustfmt` and `clippy`). With [rustup](https://rustup.rs) installed, the correct toolchain is selected automatically when you build inside the repo.
- **macOS or Linux.**
- **A C toolchain** (clang/gcc and `make`) — the SQLCipher/OpenSSL dependency is vendored and compiled from source on first build.
- **Linux only: the D-Bus development headers** — the OS keyring backend is built against `libdbus`. On Debian/Ubuntu:
  ```bash
  sudo apt-get install -y build-essential pkg-config libdbus-1-dev
  ```
  (Fedora/RHEL: `sudo dnf install gcc make pkgconf-pkg-config dbus-devel`; Arch: `sudo pacman -S base-devel pkgconf dbus`.)
  Without them the build fails in `libdbus-sys` with "failed to run custom build command".
- **Optional: [Ollama](https://ollama.com)** — for fully offline, 100% local conversations. Nothing leaves the machine with a local model.

## Install methods

### From source

```bash
git clone <repo-url>
cd enclave
cargo build --release
```

The binary is produced at `target/release/enclave`. To put it on your `PATH` instead:

```bash
cargo install --path .
```

This installs `enclave` into `~/.cargo/bin` (make sure that directory is on your `PATH`).

### Prebuilt binary

Download the release asset for your platform from the project's releases page, then:

```bash
chmod +x ./enclave
```

On macOS, ad-hoc sign the binary so the OS can remember your keychain grants (see [macOS notes](#macos-notes)):

```bash
codesign --force --sign - ./enclave
```

Then move it somewhere on your `PATH`:

```bash
sudo mv ./enclave /usr/local/bin/enclave
```

### Using the release script

[`scripts/release.sh`](../scripts/release.sh) performs a reproducible-ish release build (`--locked`, incremental disabled) and packages the artifacts:

```bash
./scripts/release.sh
```

It produces:

- `target/release/enclave` — the release binary;
- `dist/enclave` — a copy used for distribution, **ad-hoc signed** on macOS (`codesign --force --sign -`);
- `dist/enclave.sha256` — the SHA-256 checksum of `dist/enclave`;
- `dist/enclave.cdx.json` — a CycloneDX **SBOM** (only when `cargo-cyclonedx` is installed).

To sign with a real identity instead of an ad-hoc signature:

```bash
ENCLAVE_SIGN_IDENTITY="Developer ID Application: <your name>" ./scripts/release.sh
```

## First run and initial setup

On the first launch, Enclave creates its vault and asks you to choose a **master password**. This password derives the encryption key (Argon2id by default; the key is `mlock`-ed and zeroized on drop) — nothing in the vault is readable without it.

```bash
enclave tui      # full-screen UI
# or
enclave chat     # line-based chat
```

The vault lives in the per-user config/data directory:

- **macOS:** `~/Library/Application Support/dev.enclave.enclave`
- **Linux:** the XDG directories resolved via the [`directories`](https://crates.io/crates/directories) crate (under `~/.config` and `~/.local/share`).

| File | Purpose |
|------|---------|
| `vault.db` | SQLCipher database (AES-256) — chats, memory, decisions, ledger |
| `salt.bin` | Random 32-byte salt + KDF metadata |
| `keys.toml` | Local cached master key and non-keychain API keys (mode `0600`) |

Store provider credentials, inspect the resolved config, and check the database:

```bash
enclave keys set <provider>   # store an API key
enclave config                # show resolved configuration (no secrets)
enclave db                    # unlock and show database stats
```

By default the derived master key is cached locally in `keys.toml` (mode `0600`), so later launches skip the password prompt without an OS-keychain dialog. Set `use_keychain = false` in `config.toml` to require the password every time.

## Provider setup

Enclave supports `openrouter`, `openai`, `anthropic` and `ollama`.

### Remote providers (OpenRouter / OpenAI / Anthropic)

Provide an API key either through an environment variable (preferred — no keychain prompt):

```bash
export ENCLAVE_OPENROUTER_API_KEY=<your-key>
export ENCLAVE_OPENAI_API_KEY=<your-key>
export ENCLAVE_ANTHROPIC_API_KEY=<your-key>
```

The provider's standard variable (`OPENROUTER_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) is also recognised.

Or store it via Enclave (written to the local `keys.toml`, mode `0600`):

```bash
enclave keys set openrouter
enclave keys set openai
enclave keys set anthropic
```

Add `--keychain` to keep the key in the OS keychain instead:

```bash
enclave keys set openrouter --keychain
```

### Local provider (Ollama)

No API key is needed. Install Ollama, pull a model, and run offline:

```bash
ollama pull llama3.2
enclave chat --provider ollama --model llama3.2
```

## macOS notes

Enclave reads credentials lazily and only touches the OS keychain as a fallback, so a normal launch prompts at most once. The catch: if `enclave` is **unsigned**, macOS cannot remember an "Always Allow" grant — the code signature changes on every rebuild, so it re-asks for the keychain password. **Ad-hoc signing matters**, because it gives the binary a stable identity:

```bash
codesign --force --sign - ./enclave
```

Then choose **Always Allow** (not just *Allow*) on the next launch. The grant persists until you rebuild — re-sign after every rebuild. For a grant that also survives rebuilds, create a self-signed code-signing certificate (Keychain Access → Certificate Assistant → Create a Certificate → type *Code Signing*) and sign with `codesign --force --sign <cert-name> ./enclave`.

To avoid the keychain entirely, export the key as an environment variable (`ENCLAVE_<PROVIDER>_API_KEY` or the provider's `*_API_KEY`); Enclave prefers it over the keychain.

## Updating and uninstalling

**Update (from source):**

```bash
git pull
cargo build --release
```

**Uninstall the binary:** if installed with `cargo install`, run `cargo uninstall enclave`; otherwise delete the binary from your `PATH`.

**Remove your data:** Enclave stores everything in its config/data directory (see above). To securely delete the encrypted database, salt and stored keys:

```bash
enclave wipe          # asks for confirmation
enclave wipe --force  # no prompt — irreversible
```

This does not remove the binary.

## Troubleshooting

- **Expired/invalid API key or credit errors** — check your account with `enclave or credits` (OpenRouter credits, usage and limits).
- **Provider returns `401` / `403`** — the key is missing, wrong, or rejected. Re-export the env var or re-run `enclave keys set <provider>`. A `403 PII detected` comes from the provider's own content scan, not from Enclave.
- **Build errors** — confirm the pinned toolchain is active (`rustc --version` should match `rust-toolchain.toml`); installing via [rustup](https://rustup.rs) handles this automatically. A missing C compiler breaks the vendored SQLCipher/OpenSSL build.
- **macOS re-prompts the keychain every launch** — the binary is unsigned; ad-hoc sign it (see [macOS notes](#macos-notes)) and choose **Always Allow**.
- **`command not found: enclave`** — `~/.cargo/bin` (or `/usr/local/bin`) is not on your `PATH`.

## Next steps

- Project overview and features: [`README.md`](../README.md).
- Everyday usage and commands: [`docs/USAGE.md`](USAGE.md).

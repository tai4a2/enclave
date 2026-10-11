# Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        ENCLAVE                          │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │    TUI      │  │  CLI (clap)  │  │    Config     │  │
│  │ (ratatui)   │  │              │  │ (toml, dirs)  │  │
│  └──────┬──────┘  └──────┬───────┘  └───────┬───────┘  │
│         └─────────────────┴───────────────────┘          │
│                          │                               │
│  ┌───────────────────────┴───────────────────────┐      │
│  │              CORE ENGINE                      │      │
│  │  chat loop · session mgmt · message model     │      │
│  └───────────────────────┬───────────────────────┘      │
│                          │                               │
│  ┌───────────────────────┴───────────────────────┐      │
│  │           PRIVACY LAYER (the heart)           │      │
│  │  ┌──────────────────┐  ┌───────────────────┐  │      │
│  │  │ EncryptedMemory  │  │ SecureCredentials │  │      │
│  │  │ (SQLCipher)      │  │ (OS keychain)     │  │      │
│  │  └──────────────────┘  └───────────────────┘  │      │
│  └───────────────────────┬───────────────────────┘      │
│                          │                               │
│  ┌───────────────────────┴───────────────────────┐      │
│  │        PROVIDERS (pluggable, async)           │      │
│  │  OpenRouter · OpenAI · Anthropic · Ollama     │      │
│  └───────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────┘
```

## Modules

| Path | Responsibility |
|------|----------------|
| `src/main.rs` | Binary entry point, tokio runtime |
| `src/cli.rs` | Clap-derive subcommands: `chat`, `tui`, `keys`, `sessions`, `config`, `wipe` |
| `src/config.rs` | Resolved paths and settings (XDG via `directories`) |
| `src/core/engine.rs` | Chat loop: history, streaming print, in-chat commands |
| `src/core/tools.rs` | Shell proposals: parse fenced blocks, ask-always execution, timeout + output cap |
| `src/core/builtin_tools.rs` | Function-calling executors: `read_file`/`write_file`/`list_dir`/`run_shell` (+`delegate`), workspace-confined paths |
| `src/core/agents.rs` | Multi-agent MVP: personas from config, `delegate` tool, ephemeral sub-agent sessions (RAM-only) |
| `src/core/session.rs` | `Session`: RAM view + encrypted persistence |
| `src/core/message.rs` | `Message` / `Role` model (serde) |
| `src/privacy/crypto.rs` | PBKDF2-SHA256 (600k iter), AES-256-GCM, CSPRNG |
| `src/privacy/vault.rs` | `MasterKey` (zeroized), salt file, key derivation |
| `src/privacy/keys.rs` | Keychain storage for API keys and cached master key |
| `src/privacy/memory.rs` | `EncryptedMemory`: SQLCipher handle + schema + queries + stats/VACUUM |
| `docs/audit.md` | Security & privacy audit with verified findings and fixes |
| `src/privacy/export.rs` | Encrypted session export/import (`.enclave` files, AES-256-GCM + PBKDF2) |
| `src/providers/*` | `Provider` trait + 4 implementations, streaming via SSE; `chat_with_tools` (OpenAI-compatible, Anthropic tool_use, Ollama native) |
| `src/tui/` | ratatui full-screen interface: sessions sidebar, markdown rendering (`markdown.rs`), spinner, proposal panel, ask-always execution |

## Data flow (one chat turn)

1. `chat` opens the vault: salt → PBKDF2(password) → `MasterKey` (or keychain cache)
2. `EncryptedMemory::open` unlocks the SQLCipher database
3. `Session::load` decrypts and loads history into RAM
4. User input is appended to RAM and encrypted on disk in the same step
5. The provider streams the completion; chunks print as they arrive
6. The full assistant reply is persisted encrypted

## Locations

| What | Where |
|------|-------|
| Config (salt, settings) | `~/.config/enclave/` |
| Encrypted database | `~/.local/share/enclave/vault.db` |
| API keys | OS keychain, service `enclave` |

The database path is never readable without the master key: opening it with a wrong key fails (verified by `tests/privacy_memory.rs::wrong_key_cannot_open_vault`).
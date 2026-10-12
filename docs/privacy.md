# Privacy & Security Model

Enclave's threat model: **anyone with access to your disk must not be able to read your conversations** — including other apps, backups, and whoever steals your laptop.

## 1. Encrypted memory (SQLCipher)

All chat history lives in a single SQLCipher database (`vault.db`):

- AES-256-CBC page encryption, HMAC-SHA512 page integrity
- `cipher_page_size = 4096`, `kdf_iter = 256000`
- Key supplied with raw-key syntax (`PRAGMA key = "x'<hex>'"`) so SQLCipher does not re-run its own KDF on top of ours

Guarantees enforced by tests (`tests/privacy_memory.rs`):

- a wrong master key cannot open the database
- message content never appears as plaintext bytes in the raw file
- session lifecycle (create → save → read → delete) roundtrips correctly

## 2. API keys (OS keychain)

API keys are stored via the `keyring` crate in the native key store:

| OS | Backend |
|----|---------|
| macOS | Keychain |
| Windows | Credential Manager |
| Linux | Secret Service (GNOME Keyring / KWallet) |

Keys are never written to a file, never logged, and only displayed as an 8-character prefix on `keys get`.

Alternatively a key can be supplied through the environment
(`ENCLAVE_<PROVIDER>_API_KEY` or the provider's standard `<PROVIDER>_API_KEY`,
e.g. `OPENROUTER_API_KEY`). Environment variables take precedence over the
keychain, letting you avoid the macOS keychain prompt entirely; the key then
lives only in your shell environment, not on disk.

## 3. Master key

- Derived with **Argon2id** (memory-hard, 19 MiB, t=2) by default; **legacy
  PBKDF2-HMAC-SHA256 (600,000 iterations)** vaults keep working — the algorithm
  is recorded in the salt file (`ENCLAVE-KDF` header). Pick the default for new
  vaults with `kdf = "argon2id" | "pbkdf2"` in `config.toml`.
- Random 32-byte salt (`~/.config/enclave/salt.bin`)
- Held in a `MasterKey` type that is **zeroized on drop** and, best-effort,
  `mlock`-ed so it is never written to swap; the process also disables core dumps
  (`harden_process`)
- With `use_keychain = true` (default) the derived key is cached in the local
  credentials file (`keys.toml`, mode `0600`): the master password is asked only
  the first time, then later launches skip it with no OS-keychain dialog. With
  `use_keychain = false` the key is re-derived from the password on every launch
  and never stored.
- `wipe` deletes database, salt and cached keys

Trade-off: lose the password (and the cached key) → the history is unrecoverable. That is by design.

## 4. What is NOT encrypted

Be precise about the boundaries:

- **Network transit to remote providers** — chatting via OpenRouter/OpenAI/Anthropic sends your prompt to that server in transport-encrypted but provider-readable form. Providers may scan content (OpenRouter PII detection blocks requests containing personal data).
- **RAM** — decrypted messages and keys exist in memory while Enclave runs (zeroized as soon as possible).
- **Other apps on your screen** — the terminal scrollback may retain decrypted output.

**For truly sensitive conversations use the Ollama provider: 100% offline, nothing leaves the machine.**

### Shell tools

The assistant can only *propose* shell commands (` ```bash ` blocks); each one
requires your explicit approval and nothing auto-runs. Approved command output
is encrypted at rest but travels to the provider on the next turn — see
[tools.md](tools.md) for the full security model.

### Privacy guard

`src/privacy/guard.rs` scans every outgoing request for sensitive data
(emails, phones, IBANs, tax IDs, card numbers, API secrets, IPs). With the
default `guard.mode = "ask"` you see a preview and choose: send as-is,
replace each finding with a stable placeholder (`[EMAIL_1]`…), or refuse.
Redaction is applied to the whole history on every turn — placeholders stay
consistent while the original text never leaves the encrypted database.
Note: the scan is deterministic (regex + Luhn), not an AI model; sophisticated
identifiers (e.g. free-text names without structure) are out of scope.
Remote providers still receive whatever you explicitly approved.

### Attachments

Files added with `/attach` (or `--attach`) are stored **encrypted** in the same
SQLCipher database — image bytes as base64 inside the message metadata, text
files as content. **Text attachments are inlined into the prompt and scanned
by the privacy guard** just like typed text. **Images cannot be scanned** by
the guard (they are opaque bytes): treat them as you would a photo you are
about to upload to a cloud provider, and prefer a local `ollama` vision model
for anything sensitive. Images are capped at 8 MB each.

### Rules and permissions

Project rules (`AGENTS.md`) and the `[permissions]` table are resolved
**locally only**. Rule files are read from disk (`<config_dir>/AGENTS.md`, the
nearest project `AGENTS.md` up to the git root, and the local paths listed in
`instructions`); remote URLs are ignored and never fetched. Permissions are
evaluated in-process before any tool call — a `deny` rule means the command
never executes and is reported back to the model as `[denied by policy]`.

### MCP servers

MCP servers are **external processes you explicitly configure** in
`config.toml`; Enclave only connects to them over stdio and never to a remote
endpoint on its own. Tool arguments and results pass through the privacy guard
like any other text, but they are produced and consumed by third-party code —
only connect servers you trust, and keep them behind the permission model
(default `ask`).

### Long-term memory

Memories (`/remember`, the `remember` tool, `/checkpoint`, periodic autosave)
are stored **encrypted** in the same SQLCipher `vault.db` as your sessions —
never in an external service. When a memory is injected into the system prompt
it becomes outgoing context, so the **privacy guard scans it** before it reaches
a cloud provider, exactly like typed text. Memories marked `local_only`
(`/remember … --local`) are stored but **never injected**, so they cannot leave
the machine.

### Notifications

The TUI can ring the terminal bell and post a macOS notification when a reply
or a tool approval is ready (`[tui] notify`, default `true`). This is entirely
local: the bell writes to the terminal and the macOS path shells out to
`osascript`; no data is transmitted.

### Egress ledger

Every request that leaves the machine is appended to an **encrypted, tamper-evident
ledger** inside `vault.db`. Each entry stores only a **SHA-256 fingerprint** of the
serialized payload, the provider/model, a timestamp, and the guard's redaction map
(e.g. `2 EMAIL, 1 CARD`) — **never the payload or any secret in clear**, so the
ledger itself cannot leak data. Entries are chained (`prev_hash` → `hash`), so any
edit breaks the chain: `enclave ledger --verify` (CLI) or `/ledger` (TUI) detects it
and exits non-zero. Use it to audit *what* left the machine and *when*, without
storing *what* was said.

### Auto-lock, blur and clipboard

The TUI can lock itself behind the master password after a period of inactivity
(`[security] auto_lock_secs`); the transcript is replaced by a masked prompt and
unlocking re-derives the key and re-opens the encrypted DB. The view is blanked
when the terminal window loses focus, so nothing is visible in the background.
Text copied from Enclave with Ctrl-Y/`/copy` is cleared from the clipboard after
`[security] clipboard_clear_secs` (default 30s) — but only if the clipboard still
holds exactly that text. `/panic` locks and hides the transcript immediately.

### Duress password

Set `ENCLAVE_DURESS_PASSWORD` in the environment (it is **never** written to
`config.toml`). If that password is typed at the master-password prompt, Enclave
opens a **separate decoy vault** at `<config>/decoy/` instead of the real one,
giving plausible deniability under coercion. When a duress password is configured
the "unlock once" cache is bypassed, so a password is always required.

### Command sandbox

Approved shell commands (markdown proposals, the agentic `run_shell` tool,
`!command`) run inside a macOS `sandbox-exec` jail: file reads are allowed,
writes are limited to the workspace and temporary directories, and — with
`[tools] sandbox = "strict"` — network access is blocked. Human approval remains
the primary control; the sandbox reduces the blast radius of an
approved-but-malicious command or a simple mistake. On non-macOS platforms the
command runs normally after approval.

### Taint tracking

The privacy guard redacts a message at the moment you choose to send it. Taint
tracking extends that protection over time: any user message (or text
attachment) in which the guard found sensitive data is marked *tainted* and
persisted as such in the encrypted database. On every subsequent turn the engine
re-applies the redactor to tainted messages automatically — no prompt, stable
placeholders — so a secret that entered the context once is never transmitted
verbatim again, even if you would otherwise have sent it as-is. This is enforced
by `ChatEngine::outgoing_messages` and can be turned off with
`[guard] taint = false`. Tainted data stays fully readable locally; only the
remote egress is sanitised.

## 5. Telemetry

Zero. No analytics, no crash reporting, no update pings, no logging of message content.

## 6. Verification

```bash
cargo test
```

The integration tests assert the privacy properties directly against real SQLCipher databases in temp directories.
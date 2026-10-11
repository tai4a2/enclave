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

- Derived with **PBKDF2-HMAC-SHA256, 600,000 iterations**, random 32-byte salt (`~/.config/enclave/salt.bin`)
- Held in a `MasterKey` type that is **zeroized on drop**
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

## 5. Telemetry

Zero. No analytics, no crash reporting, no update pings, no logging of message content.

## 6. Verification

```bash
cargo test
```

The integration tests assert the privacy properties directly against real SQLCipher databases in temp directories.
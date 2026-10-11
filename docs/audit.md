# Security & Privacy Audit — Enclave 0.1.0

*Audit performed 2026-10-10 on the current codebase. Severity: 🔴 critical,
🟠 medium, 🟡 low, ✅ good practice verified.*

## Summary

| Area | Verdict |
|------|---------|
| Encryption at rest (SQLCipher) | ✅ solid (AES-256, HMAC-SHA512, dedicated KDF params) |
| Master key derivation | ✅ PBKDF2-HMAC-SHA256, 600k iterations, 32B random salt |
| Keychain cache | 🔴 → ✅ **fixed in this audit** (password was never verified) |
| Export files | ✅ password + fresh salt per file, no plaintext (tested) |
| Shell tools | 🟠 residual prompt-injection risk — mitigated by ask-always |
| Network to providers | 🟠 inherent: content leaves the machine (documented) |
| Zeroization | 🟡 master key yes; message contents in RAM no |
| Telemetry | ✅ zero |
| Supply chain | 🟡 not scanned by `cargo audit` in CI yet |

## Verified good practices

1. **Database**: SQLCipher with `cipher_page_size 4096`, `kdf_iter 256000`,
   `HMAC_SHA512` + `PBKDF2_HMAC_SHA512`. The raw key is applied with
   `PRAGMA key` hex syntax (no double KDF). A wrong key cannot even open the
   file — tested in `tests/privacy_memory.rs` and `tests/db.rs`.
2. **No plaintext on disk**: integration tests assert secrets/emails are
   absent from the raw ciphertext file bytes.
3. **Master key**: 32 random bytes, PBKDF2-600k from password + 32B random
   salt, zeroized on drop (`MasterKey`).
4. **API keys** live in the OS keychain (service `enclave`), never in the
   config file or environment.
5. **Export/import**: each file uses a fresh random salt + password-derived
   key; magic/version validated; wrong password rejected before any session
   is created (tested).
6. **Tools**: nothing executes without explicit approval; hard timeout with
   `kill_on_drop`; output capped; tool output cannot re-trigger proposals.
7. **Wipe**: removes db, salt, config, keychain entries.
8. **No telemetry**: no network calls other than provider/chat and the
   public OpenRouter model catalogue (no user content in that call).

## Findings fixed in this audit

### 🔴 F1 — Keychain cache bypassed password verification (fixed)

`Vault::derive_key(use_keychain=true)` returned the keychain-cached key
**without checking the typed password** — the "Master password:" prompt was
cosmetic. **Fix**: the cached key is now accepted only if the typed password
derives exactly the same key (constant-time comparison, `crypto::ct_equal`).
Wrong password → `auth error: wrong master password`. Regression test in
`tests/vault.rs`.

### 🟠 F2 — Deleted ciphertext lingered on disk (mitigated)

`DELETE` marks pages free; the encrypted file kept old ciphertext until
compaction. **Mitigation**: `sessions delete --purge`, `sessions wipe-all`
and `sessions vacuum` now run `VACUUM`, removing freed pages from the file.
Deleting is still not a secure shred of a physical disk (APFS snapshots,
Time Machine, SSD wear leveling are outside the process's control).

### 🟡 F3 — `enclave wipe` unlinks files without overwriting (accepted)

On APFS + SSD the OS guarantees are weak anyway; the DB is encrypted, so the
residual file is ciphertext without the key (salt is deleted too, so the old
password can never derive the key again). Accepted risk, documented.

## Residual risks (by design, documented)

| Risk | Severity | Boundary |
|------|----------|----------|
| Content travels to remote providers (OpenRouter/OpenAI/Anthropic) | 🟠 | use `--provider ollama` for sensitive work |
| Tool output is sent back to the provider on the next turn | 🟠 | same mitigation; tools are ask-always |
| Prompt injection: a malicious page can make the model *propose* a dangerous command | 🟠 | approval is human-only; review commands like `curl \| sh` |
| Approved commands run with user privileges (`sh -c`), no sandbox | 🟠 | the boundary is explicit consent, not isolation |
| RAM holds decrypted messages while running | 🟡 | unavoidable for a chat CLI; keys are zeroized, messages are not |
| Terminal scrollback retains rendered output | 🟡 | outside process control |
| Keychain items are readable by any process the user approves | 🟡 | standard macOS tradeoff |
| PBKDF2-600k vs Argon2id (available in deps) | 🟡 | PBKDF2-600k is within OWASP guidance; Argon2id migration is a possible future improvement |

## Recommendations (next iterations)

1. Add `cargo audit` / `cargo deny` to CI (supply-chain scanning).
2. Consider Argon2id for new vaults (keep PBKDF2 for backward compat).
3. Consider a "sensitive session" flag that refuses remote providers.
4. Optional: OS file-permission check on config dir (0700) at startup.
5. Second-line guard with a decision model (Jev / TypeSafe AI) — see
   [jev-idea.md](jev-idea.md) for the recorded design and the privacy
   paradox to solve first.

## How to verify the audit claims

```bash
cargo test                                  # 55 tests, incl. privacy properties
strings "$(ls ~/Library/Application\ Support/dev.enclave.enclave/vault.db)" | grep -i <secret>   # nothing
./dist/enclave db                           # file layout + stats after unlock
```
# Security Policy

Enclave is a privacy-first AI CLI: encryption is the main feature, not an
afterthought. We take security reports seriously and are grateful to anyone who
reports an issue responsibly.

## Supported versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

Only the latest `0.1.x` release receives security fixes. Please reproduce on the
most recent release (and, when possible, on `main`) before reporting.

## Reporting a vulnerability

**Please report privately — never in a public issue, discussion, or pull request.**

Preferred channel: use GitHub's **Private vulnerability reporting** /
**Security Advisories** for this repository (the *Security* tab → *Report a
vulnerability*). This keeps the report confidential and lets us coordinate a fix
and a disclosure.

If GitHub private reporting is unavailable (for example if you are reading a
mirror of this repository), open a **minimal** public issue asking the
maintainer to get in touch — without any vulnerability details — and a private
channel will be arranged.

If you want to send an encrypted report, request the maintainer's PGP key in the
private advisory thread first (do **not** include exploit details in any
unencrypted message).

> **Never paste secrets, API keys, tokens, private keys, personal data (PII),
> real conversations, or the contents of your `vault.db` into a public issue.**
> Sanitise everything before posting, and prefer the private channels above.

## What to include in a report

A good report helps us triage quickly. Please include:

- A short description of the issue and the impact you believe it has.
- The affected version (`0.1.x` / commit hash) and platform/OS.
- Clear steps to reproduce, ideally a minimal proof of concept.
- Relevant configuration (`config.toml` with secrets removed) and command lines.
- Any logs or screenshots, with secrets and PII redacted.
- Your assessment: which security property is broken (confidentiality at rest,
  key handling, guard bypass, sandbox escape, network egress, etc.).
- Whether you are willing to be credited, and under what name.

Please avoid including real user data. If a crash dump or database is needed,
coordinate with us privately and share a minimal, synthetic reproduction
instead.

## Response timeline

We aim to:

- **Acknowledge** your report within **3 business days**.
- **Triage and confirm** (or explain why it is out of scope) within **7 business
  days**.
- Provide a **remediation plan** with a target date, and keep you updated on
  progress.
- **Disclose** the issue publicly once a fix is released, crediting you unless
  you prefer to stay anonymous.

These are best-effort targets for a small project, not a contractual SLA.

## Scope

In scope:

- The application itself (the `enclave` binary and library).
- **Encryption at rest** — the SQLCipher vault, KDF/master-key handling,
  key caching, zeroization, encrypted export/import.
- The **privacy guard** — PII detection, redaction/placeholder logic, taint
  tracking, egress policy, DLP judge, prompt-injection canary and routing.
- The **command sandbox** (`sandbox-exec` jail) and the permission model.
- The **local web UI** (`enclave serve`) — its loopback binding and per-run
  token authentication.
- The encrypted **egress ledger** (integrity/hash-chain verification).
- Local storage of memories, decisions, RAG chunks and attachments.

Out of scope:

- **Third-party providers** (OpenRouter, OpenAI, Anthropic, and any MCP server)
  — their handling of data you choose to send is theirs, not ours.
- **Your machine** — a compromised OS, malware, another app reading your screen
  or RAM, terminal scrollback, backups/snapshots, or a weak master password.
- **Dependency vulnerabilities** — report those upstream. We track them with
  [`cargo-audit`](https://github.com/rustsec/rustsec/tree/main/cargo-audit)
  (RUSTSEC advisories) and
  [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny); both run in CI
  (see `.github/workflows/ci.yml`). If a vulnerable dependency affects Enclave
  in a way we can mitigate, tell us too.
- Social engineering, physical access, and denial-of-service against your own
  machine.

## Threat model

Enclave assumes **anyone with access to your disk must not be able to read your
conversations** — including other apps, backups, and whoever steals your laptop.
The full model, boundaries, and residual risks are documented in
[docs/privacy.md](docs/privacy.md) (and the point-in-time assessment in
[docs/audit.md](docs/audit.md)). Notably:

- **In transit to a remote provider is out of our control once you send.** If a
  provider's servers are compromised or scan your content, that is outside
  Enclave's boundary. Use the local Ollama provider (or air-gap mode) for
  genuinely sensitive work.
- **RAM** holds decrypted content while Enclave runs; keys are zeroized and
  `mlock`-ed, but message buffers cannot all be. This is an inherent limit of a
  chat CLI.
- **Remote URLs are never fetched** for rules or commands; only the local disk
  is read.

## Safe harbour

We will not pursue or support legal action against researchers who act in good
faith: who make a reasonable effort to avoid privacy violations, data
destruction and service interruption, and who report findings privately before
public disclosure. Thank you for helping keep Enclave users safe.

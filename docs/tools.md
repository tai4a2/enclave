# Tools — security model

Enclave lets the assistant *propose* shell commands but never lets it *run*
anything on its own. This document describes the exact security properties.

Enclave has two tool mechanisms:

1. **Proposals mode** (default) — markdown ` ```bash ` blocks reviewed by the
   human, executed via `sh -c` (below).
2. **Agentic mode** (`enclave chat --agent` or `tools.mode = "agent"`) — real
   function calling: the model returns structured tool calls
   (`read_file`, `write_file`, `list_dir`, `run_shell`), Enclave executes
   them only after the same ask-always approval, and feeds results back
   (max 8 iterations). File paths are canonicalized and must resolve inside
   the current workspace (`..` and outside-absolute paths are rejected).
   The privacy guard redacts tool arguments and results like any other
   outgoing text. Multi-agent `delegate` runs sub-agents with **ephemeral,
   RAM-only sessions** and cannot recurse further (depth limit 1).

## Design: proposals, not function calling

The assistant emits fenced ` ```bash ` blocks in its reply. Enclave parses
them (`src/core/tools.rs`) and offers an interactive prompt. This works with
every provider — including local Ollama — and makes auto-execution
structurally impossible: the model cannot "call" a tool, it can only write
text that a human reviews.

## Guarantees

| Property | Mechanism |
|----------|-----------|
| No execution without consent | every proposal requires `[y]es`; default is *no*; EOF on stdin is treated as *no* |
| No runaway commands | hard timeout (`tools.timeout_secs`, default 30s); the child is killed via `kill_on_drop` |
| No history flooding | output capped per stream (`tools.max_output_bytes`, default 8192B) before display and before persistence |
| No hidden execution | the exact command line is printed before the prompt |
| Kill switch | `enclave chat --no-tools`, or `tools.enabled = false` in `config.toml` |
| No re-proposal loops | tool output is wrapped in `[tool] … [/tool]` and is not parsed for proposals |

## What is NOT sandboxed

An approved command runs with **your user privileges** under `sh -c`, in the
current working directory. There is no filesystem jail, no network filter,
no seccomp. The security boundary is the explicit human approval of the exact
command text — review it like a `curl | sh`.

## Privacy boundary

Tool output enters the encrypted history (AES-256 at rest). On the next turn
it is sent to the provider: with OpenRouter/OpenAI/Anthropic that means the
command output (file contents, `env`, …) leaves the machine in transit.
For sensitive work use `enclave chat --provider ollama` — then tool I/O never
leaves the device.

## Disabling completely

```toml
# ~/.config/enclave/config.toml (macOS: ~/Library/Application Support/enclave/config.toml)
[tools]
enabled = false
```

or run every chat with `--no-tools`.

## Tests

`tests/tools.rs` + unit tests in `src/core/tools.rs` cover: proposal parsing
(including unclosed fences from partial streams), exit codes, stderr capture,
timeout kill, output caps, UTF-8-safe truncation, and the non-re-proposal of
tool output.
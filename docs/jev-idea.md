# Idea: Jev (TypeSafe AI) as second-line privacy guard — TO IMPLEMENT

> Recorded on user request ("scrivi questa mia idea la riprendiamo") — pick this
> back up in a future session. Not implemented yet.

## The idea

Affiancare alle regex del privacy guard (`src/privacy/guard.rs`) un **modello
decisionale** per intercettare ciò che le regex non colgono (nomi propri in
testo libero, contesto sanitario/finanziario, indirizzi…): **Jev**, il
"System One Model" di TypeSafe AI.

## What Jev is (verified Oct 2026)

- Does NOT generate text: takes `state` + typed `questions`, returns **typed
  decisions** (Choice, Score, yes/no) with **calibrated probabilities**. No
  hallucination, no type errors.
- Fast: 70–500 ms per call. Cheap: $0.042/MTok input, output free.
- Hosted API: `docs.typesafe.ai`, console `console.typesafe.ai`. Public API
  since 21 Sep 2026 (founded by Diogo Almeida, ex-OpenAI).
- Declared use cases include: "score, judge, verify, **guardrail**, detect
  jailbreaks" — exactly our use case.

## The privacy paradox (must be solved in the design)

Jev is a **hosted API**: using it as a pre-send scanner would send the very
data we protect to a third party *before* user consent — the guard would
cause the leak it exists to prevent.

## Two architectures

### A) Pre-send scanner (opt-in, disclosed)
- Jev analyzes every outgoing message: "contains PII? which types?" →
  calibrated probability; catches regex blind spots.
- MUST be explicit opt-in (`[guard] jev = true` + API key
  `enclave keys set typesafe`) and disclosed in the popup: "messages are
  also analyzed by typesafe.ai". Never default-on.

### B) Redaction verifier (privacy-clean — RECOMMENDED FIRST)
- After the user picks *placeholders*, send the **already-redacted** text to
  Jev: "is anything sensitive still present?" → if probability > threshold,
  warn "redaction may be incomplete" (suggest review/refuse).
- Redacted text is already authorized for egress → zero additional exposure.
- Bonus: on the *send-as-is* path (already approved), Jev can do a final
  pre-provider check.

Recommended plan: implement **B always** (when configured), **A as a separate
flag defaulting to off**.

## Implementation notes

1. Fetch `docs.typesafe.ai` for the exact request/response schema
   (`state`, `questions`, Choice/Score types, auth).
2. Store key in keychain: `enclave keys set typesafe`.
3. Config: `[guard] jev = false`, `jev_threshold = 0.7` (tune).
4. Merge Jev findings into the existing guard popup/overlay (CLI panel +
   TUI overlay): show as "Jev: possible <type> (87%)" alongside regex
   findings; keep regex findings authoritative.
5. Async call must respect the 500ms budget; on timeout/error degrade
   gracefully (regex-only) — guard must never block the chat because Jev is down.
6. New integration point: `ChatEngine::outgoing_messages` flow + guard gate
   in `cli.rs::guard_gate` and `tui/app.rs` guard phase.
7. Docs: update `docs/privacy.md` (third-party boundary disclosure),
   `README.md`, `docs/audit.md` residual risks.

## Status

- [ ] API schema fetched and reviewed
- [ ] Config + keychain wiring
- [ ] Redaction-verifier (B)
- [ ] Pre-send scanner (A, opt-in)
- [ ] Tests + docs + audit update
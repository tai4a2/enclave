# Enclave — materiali di promozione

## Post LinkedIn (italiano — pronto da incollare)

 🔐 Ho pubblicato Enclave: un assistente AI per il terminale che mette la privacy al primo posto.

 La maggior parte degli AI CLI salva la cronaca in chiaro e le API key in file leggibili. Enclave fa il contrario:

 · Memoria cifrata (SQLCipher AES-256, Argon2id, mlock + zeroize)
 · Privacy guard: email, carte, segreti e nomi vengono rilevati PRIMA dell'invio — invii, oscuri o rifiuti
 · Taint tracking: i dati oscurati restano oscurati nei turni successivi
 · Egress ledger: ogni richiesta in uscita è loggata in un registro cifrato a catena di hash — puoi vedere (e dimostrare) esattamente cosa lascia il tuo Mac
 · Air-gap: puoi vietare i provider remoti e lavorare solo con modelli locali (Ollama), completamente offline
 · Git per le conversazioni: branch, merge, diff e blame sulla chat
 · TUI + web UI locale, 243 test, MIT

 Rust, open source, nessuna telemetria.

 👉 https://github.com/tai4a2/enclave

 #Privacy #OpenSource #Rust #AI #CyberSecurity #LLM #DataProtection #InfoSec #DevTools #GDPR #AIAct #CodingAssistant #OpenRouter #Ollama

## Post LinkedIn (english — alternativa)

 🔐 I just released Enclave: a privacy-first AI coding assistant for your terminal.

 Most AI CLIs store your history in plaintext and your keys in plain files. Enclave does the opposite:

 · Encrypted memory (SQLCipher AES-256, Argon2id, mlock + zeroize)
 · Privacy guard: emails, cards, secrets and names detected BEFORE they leave — send, redact or refuse
 · Taint tracking: redacted data stays redacted on later turns
 · Hash-chained egress ledger: see and prove exactly what left your machine
 · Air-gap mode: go fully local (Ollama), nothing ever leaves
 · Git for conversations: branch, merge, diff, blame your chats
 · TUI + local web UI, 243 tests, MIT licensed

 Rust, open source, zero telemetry.

 👉 https://github.com/tai4a2/enclave

 #Privacy #OpenSource #Rust #AI #CyberSecurity #LLM #DataProtection #InfoSec #DevTools #CodingAssistant

## Consigli per il post

- Incolla il link al repo nel post o nel primo commento (LinkedIn lo pesa nel ranking)
- Allega `assets/tui.png` o `assets/banner.png` come immagine: i post con screenshot funzionano molto meglio
- Miglior momento: martedì-giovedì, 8:30-10:30
- Pubblica la Release v0.1.0 su GitHub PRIMA del post (i click su "Releases" oggi trovano 0 release)

## GitHub — topics da impostare

Repo → About (ingranaggio) → Topics, oppure:

```bash
gh repo edit tai4a2/enclave --add-topic privacy --add-topic llm --add-topic cli \
  --add-topic rust --add-topic ai --add-topic security --add-topic privacy-first \
  --add-topic data-protection --add-topic sqlcipher --add-topic ollama \
  --add-topic openrouter --add-topic pii --add-topic taint-tracking --add-topic air-gap \
  --add-topic secrets --add-topic developer-tools --add-topic tui --add-topic code-assistant \
  --add-topic agentic-ai --add-topic encryption
```

(serve `gh auth login` — il token nel keyring è attualmente invalido; in alternativa si impostano dall'interfaccia web, max 20 topics)

Suggerimento anche per la **description** del repo (About):

> Privacy-first AI coding assistant for your terminal — encrypted memory, PII guard before send, hash-chained egress ledger, air-gap/local models. Rust, MIT.

## Homepage URL del repo (About → Website)

Puoi impostare lo stesso URL del repo, oppure (se un giorno pubblichi una landing) il sito dedicato.
# Roadmap — Memoria di progetto e Gestione del contesto

Idee e ondate per evolvere Enclave da "assistente con memoria" a **secondo cervello
di progetto**, privacy-first. Fonde le idee su memoria/contesto con quelle emerse
in precedenza (blast-radius, context firewall, proof-of-redaction, ecc.).

Principio guida: **tutto locale e cifrato per default**; nulla esce dalla macchina
senza consenso esplicito, coerente con `docs/security-roadmap.md`.

---

## Cosa c'è già (base di partenza)

- **Supermemory**: tabella `memories` cifrata, `/remember`, `/memory`, `/forget`,
  `/checkpoint`, autosave periodico, `working_session`, iniezione nel system prompt.
- **RAG locale con ACL per file**: `rag_chunks`, `/rag index|search|status|clear`,
  embedding opzionale + fallback keyword (BM25-like).
- **Contesto**: `compact()` (riassunto gerarchico grezzo), `undo/redo/retry`,
  branch di conversazione ("conversation git"), interfaccia `/graph`.
- **Ledger egress** con catena di hash + proof-of-redaction; **guard** (regex+NER),
  **taint**, **policy**, **air-gap**, **canary** anti-injection, **routing** locale.
- **Info panel** con stima contesto (~token · righe), db, sessioni, messaggi, todo.

---

## A. Idee per la MEMORIA DI PROGETTO

1. **Grafo di conoscenza di progetto (cifrato).** Non memorie piatte ma entità
   tipizzate (file, moduli, decisioni, persone, task, bug) + archi tipizzati
   (`usa`, `dipende-da`, `deciso-in`, `risolve`). Costruito incrementalmente e
   interrogabile ("perché abbiamo scelto X?", "cosa tocca `engine.rs`?").
2. **Decision Log / ADR automatico.** Rileva le decisioni nella conversazione
   ("usiamo axum", "scartiamo Y"), le salva come ADR con contesto + motivazione +
   data + sessione, e le re-inietta quando rilevanti. Risponde a "perché è così?".
3. **Code-map con rilevamento di staleness.** Indice simboli/file → hash. Quando un
   file cambia, la memoria collegata è marcata *stale* e proposta per aggiornamento.
   Elimina il classico "contesto vecchio che confonde il modello".
4. **Apprendimento delle convenzioni dal repo.** Estrae stile e convenzioni (naming,
   gestione errori, layout test) in una "scheda di stile di progetto" sempre
   iniettata, come un AGENTS.md auto-derivato e auto-corretto.
5. **Memoria con provenienza.** Ogni memoria registra origine (file, commit,
   sessione) → auditabile e garbage-collectable in modo sicuro.
   **Stato: parziale.** Le memorie/decisioni sono già taggate con `source_session`
   e l'egress ledger registra la provenienza verso l'esterno; il Context Inspector
   (vedi #16) mostra *cosa* viene iniettato e da quale parte. Manca l'origine
   file/commit per singola memoria.
6. **Decadimento e rinforzo (spaced repetition dei fatti).** Confidenza + recency:
   le memorie usate si rinforzano, quelle inutilizzate decadono; i conflitti
   emergono e vengono risolti dall'utente.
7. **Memoria di progetto condivisa in team (E2EE).** Grafo condiviso via sync
   crittografato end-to-end (CRDT): la conoscenza del team resta privata al team.
8. **Recall per intento.** Quando affronti un problema simile a uno passato, Enclave
   rispolvera automaticamente la soluzione ("l'avevi risolto 3 settimane fa, così").

## B. Idee per la GESTIONE DEL CONTESTO

9. **Context budgeter con quota per fonte.** Ogni turno un budget ripartito tra
   system / memoria di progetto / RAG / storico, con packing deterministico per
   priorità e **composizione del contesto visibile in tempo reale** (barra).
   **Stato: implementato (v1).** Budget soft in token (`[context] budget_tokens` +
   `warn_pct`, default 80) con stima token (caratteri/4) e barra di utilizzo in
   `enclave context`, TUI `/context` (riga info panel che diventa gialla/rossa) e
   web `/context`. (Manca ancora la quota per singola fonte e il packing
   deterministico.)
10. **Recupero ibrido = "contesto minimo sufficiente".** Invece di incollare tutto lo
    storico: selezione semantica (embedding locali) + lessicale (BM25) sotto un tetto
    di token. Meno costo, meno leakage, risposte più pulite.
11. **Riassunto gerarchico con recall.** Livelli turno → episodio → digest di
    progetto; l'originale resta cifrato e "espandibile" on demand (MemGPT-style, ma
    locale).
12. **Prefisso stabile cache-aware.** Tieni un prefisso fisso (system + regole +
    memoria) per massimizzare il **prompt caching** del provider; cambia solo il
    delta → più economico, più veloce; mostra il *cache hit rate*.
13. **Scratchpad con promozione.** Set di lavoro volatile in RAM per il task, promosso
    a memoria di progetto solo quando lo "committi": separazione netta effimero/durabile.
14. **Focus modes (coding / writing / ops).** Profili che riconfigurano cosa viene
    auto-iniettato (coding → code-map + convenzioni + diff recenti; ops → runbook + log).
15. **Context firewall per-chunk + least-context.** Ogni frammento recuperato è
    permesso-gated e minimizzato: esce solo ciò che serve, non il file intero.
16. **"Perché è nel contesto?"** Ogni elemento iniettato mostra la sua motivazione e
    si può spegnere con un click; un pulsante "minimizza contesto" taglia l'accessorio.
    **Stato: implementato (v1).** `Context Inspector`: `ChatEngine::context_report()`
    + `system_parts()` espongono la composizione del messaggio di sistema (prompt,
    regole, piano, memoria, decisioni, anti-injection) con anteprima e dimensione,
    più storico/redazioni/taint. CLI `enclave context [--session]`, TUI `/context`,
    web `/api/context` + overlay. (Manca ancora lo "spegnimento" per-elemento.)
17. **Reranker locale appreso (feedback loop).** Traccia quali frammenti hanno davvero
    influenzato la risposta e impara un reranker on-device: migliora con l'uso.
18. **Provenienza visibile nella risposta.** Il modello cita quale memoria/chunk ha
    usato; l'UI collega le due cose con badge.
19. **Replay deterministico + controfattuale.** Rigira un turno con contesto diverso
    per capire se la risposta cambia (debug di memoria/contesto). Si sposa col ledger.

## C. Idee precedenti da incrociare

20. **Privacy Blast-Radius** (dashboard forense dal ledger: cosa è uscito, quando,
    verso chi, con quali redazioni + checklist di rotazione segreti).
21. **Trust labels** pervasive su tutto il testo esterno (tool/file/RAG/web) +
    ri-approvazione delle azioni nate da contenuto non fidato.
22. **Local Model Committee** (2-3 modelli locali a confronto, segnalazione divergenze).
23. **Proof-of-redaction / selective disclosure** (commitment dell'originale +
    versione redatta verificabile).
24. **Hardware-backed unlock** (Secure Enclave / YubiKey / WebAuthn).
25. **Ricerca semantica** su sessioni+memoria (embedding on-device).
26. **Voice on-device** (whisper.cpp locale), chiavi provider effimere, budget guard,
    "privacy score" per sessione.
27. **Build riproducibili + release firmate + SBOM**; **sync E2EE tra dispositivi**.

---

## Valutazione (punteggi)

Scala: **Innovazione** 1-5, **Utilità** 1-5, **Sforzo** S/M/L/XL.
**Punteggio = (I+U) × peso(sforzo)**, pesi S=1.0, M=0.8, L=0.6, XL=0.4 (max 10).
Premia impatto alto + fattibilità a breve.

| # | Idea | Inn | Uti | Sforzo | Punteggio |
|---|------|-----|-----|--------|-----------|
| 2 | Decision Log / ADR automatico | 5 | 5 | M | **8.0** |
| 20 | Privacy Blast-Radius (forense dal ledger) | 4 | 4 | S | **8.0** |
| 5 | Memoria con provenienza | 3 | 4 | S | 7.0 |
| 16 | "Perché è nel contesto?" | 4 | 3 | S | 7.0 |
| 26b | Chiavi provider effimere | 3 | 4 | S | 7.0 |
| 26d | Privacy score per sessione | 3 | 4 | S | 7.0 |
| 3 | Code-map + staleness | 3 | 5 | M | 6.4 |
| 9 | Context budgeter + composizione | 3 | 5 | M | 6.4 |
| 12 | Prefisso cache-aware (+ cache hit) | 4 | 4 | M | 6.4 |
| 19 | Replay deterministico + controfattuale | 5 | 3 | M | 6.4 |
| 21 | Trust labels pervasive | 4 | 4 | M | 6.4 |
| 22 | Local Model Committee | 5 | 3 | M | 6.4 |
| 14 | Focus modes | 3 | 3 | S | 6.0 |
| 26a | Voice on-device | 3 | 3 | S | 6.0 |
| 26c | Budget/token guard | 2 | 4 | S | 6.0 |
| 4 | Convenzioni dal repo | 3 | 4 | M | 5.6 |
| 6 | Decadimento + rinforzo | 4 | 3 | M | 5.6 |
| 13 | Scratchpad con promozione | 4 | 3 | M | 5.6 |
| 18 | Provenienza visibile nella risposta | 4 | 3 | M | 5.6 |
| 24 | Hardware-backed unlock | 3 | 4 | M | 5.6 |
| 25 | Ricerca semantica (embedding) | 2 | 5 | M | 5.6 |
| 1 | Grafo di conoscenza cifrato | 5 | 4 | L | 5.4 |
| 8 | Recall per intento | 5 | 4 | L | 5.4 |
| 10 | Recupero ibrido / contesto minimo | 4 | 5 | L | 5.4 |
| 15 | Context firewall per-chunk + least-context | 5 | 4 | L | 5.4 |
| 11 | Riassunto gerarchico con recall | 4 | 4 | L | 4.8 |
| 17 | Reranker locale appreso | 5 | 3 | L | 4.8 |
| 27a | Build riproducibili + SBOM | 2 | 3 | M | 4.0 |
| 7 | Memoria di progetto E2EE in team | 5 | 3 | XL | 3.2 |
| 27b | Sync E2EE multi-dispositivo | 4 | 3 | XL | 2.8 |

### Lettura del punteggio

- **Fai subito (alto ROI):** #2 Decision Log, #20 Blast-Radius, #5 Provenienza,
  #16 "Perché nel contesto?", #26b chiavi effimere, #26d privacy score.
- **Fondamenta ad alto impatto (sforzo medio):** #3 code-map, #9 budgeter,
  #12 prefisso cache-aware, #21 trust labels.
- **Investimenti strategici (pesanti ma di peso):** #1 grafo di conoscenza,
  #10 recupero ibrido, #15 context firewall, #8 recall per intento, #22 local
  model committee — da pianificare come tappe dedicate, non come "quick win".
- **Rimandabili:** #27b sync E2EE, #7 memoria E2EE di team (dipendono da infra di
  sync e da un modello di minaccia multi-utente che oggi non c'è).

---

## ONDATE DA IMPLEMENTARE

### Ondata 0 — Quick win (sforzo S, alto segnale)
- **Privacy score per sessione** [#26] — aggrega dati già esistenti (ledger, guard,
  token remote/local).
- **Trust labels** [#21] — badge UI sul testo non fidato; riusa canary/injection.
- **Composizione del contesto in info panel** [#9, prima parte] — quota per fonte.
- **Memoria stale-aware** [#3, prima parte] — hash dei file, marcatura stale.
- **Chiavi provider effimere** [#26] — RAM-only, auto-shred a fine sessione.

### Ondata 1 — Fondamenta memoria di progetto (sforzo M)
- **Grafo di conoscenza cifrato** [#1] — schema entità/archi su SQLCipher + query.
- **Decision Log / ADR** [#2] — cattura + re-iniezione + "perché è così?".
- **Code-map + staleness** [#3] — completamento.
- **Convenzioni dal repo** [#4] — scheda stile auto-derivata.
- **Provenienza memoria + decadimento/rinforzo** [#5, #6].
- **Ricerca semantica** [#25] — embedding locali con fallback BM25.

### Ondata 2 — Motore di gestione del contesto (sforzo M/L)
- **Context budgeter + composizione visibile** [#9] — completamento.
- **Recupero ibrido / contesto minimo** [#10] — sostituisce l'incollaggio integrale.
- **Riassunto gerarchico con recall** [#11] — livelli + espansione on demand.
- **Scratchpad con promozione** [#13].
- **Focus modes** [#14].
- **Prefisso cache-aware + cache hit rate** [#12].

### Ondata 3 — Innovazione / sperimentale (sforzo M/L)
- **Context firewall per-chunk + least-context** [#15].
- **"Perché è nel contesto?"** [#16].
- **Reranker locale appreso** [#17].
- **Local Model Committee** [#22].
- **Recall per intento** [#8].
- **Provenienza visibile nella risposta** [#18].

### Ondata 4 — Fiducia, verificabilità, distribuzione (sforzo M/L)
- **Privacy Blast-Radius** [#20].
- **Proof-of-redaction** [#23].
- **Replay deterministico + controfattuale** [#19].
- **Memoria di progetto E2EE in team** [#7].
- **Hardware-backed unlock** [#24].
- **Voice on-device / budget guard** [#26].
- **Build riproducibili + SBOM + sync E2EE multi-dispositivo** [#27].

---

## Shortlist consigliata (partire da qui)

1. **Privacy Blast-Radius** [#20] — quasi tutto già nel ledger, impatto "wow".
2. **Privacy score + Trust labels** [#26, #21] — visibilità immediata del valore privacy.
3. **Context budgeter + composizione** [#9] — fondamento per tutta l'Ondata 2.
4. **Grafo di conoscenza + Decision Log** [#1, #2] — il salto da "memoria" a "cervello".

> Nota compliance: per la distribuzione pubblica valgono le raccomandazioni CRA già in
> `docs/security-roadmap.md` (FOSS non commerciale in genere fuori scope; B11 come base).

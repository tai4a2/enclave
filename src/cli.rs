//! Command line interface (clap) and command dispatch.

use std::io::Write;

use clap::{Parser, Subcommand};

use crate::config::{Paths, Settings};
use crate::core::engine::ChatEngine;
use crate::core::session::Session;
use crate::error::{EnclaveError, Result};
use crate::privacy::vault::MasterKey;
use crate::privacy::{EncryptedMemory, SecureCredentials, Vault};
use crate::providers::known_providers;

/// Top-level CLI.
#[derive(Parser, Debug)]
#[command(name = "enclave", version, about = "Privacy-first AI CLI with encrypted memory")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Available commands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start an encrypted chat (line-based).
    Chat {
        #[arg(short, long)]
        model: Option<String>,
        #[arg(short, long)]
        provider: Option<String>,
        #[arg(short, long)]
        session: Option<String>,
        /// Do not read/write the master key from the OS keychain.
        #[arg(long)]
        no_keychain: bool,
        /// Ignore shell commands proposed by the assistant (no execution prompts).
        #[arg(long)]
        no_tools: bool,
        /// Send messages without the privacy-guard scan (not recommended).
        #[arg(long)]
        no_guard: bool,
        /// Agentic mode: real function calling with the built-in tool set.
        #[arg(long)]
        agent: bool,
        /// Reasoning effort hint for providers that support it: low|medium|high.
        #[arg(long)]
        effort: Option<String>,
        /// Attach a file to the first message (repeatable). Images go to
        /// multimodal models; text files are inlined and guard-scanned.
        #[arg(long = "attach", value_name = "PATH")]
        attach: Vec<String>,
        /// Auto-approve tool calls unless the permission policy denies them.
        #[arg(long)]
        auto: bool,
        /// Plan mode: read-only, mutating tools are refused.
        #[arg(long)]
        plan: bool,
    },
    /// Launch the full-screen terminal UI.
    Tui {
        #[arg(short, long)]
        model: Option<String>,
        #[arg(short, long)]
        provider: Option<String>,
        #[arg(short, long)]
        session: Option<String>,
        #[arg(long)]
        no_keychain: bool,
        /// Ignore shell commands proposed by the assistant (no execution prompts).
        #[arg(long)]
        no_tools: bool,
        /// Send messages without the privacy-guard scan (not recommended).
        #[arg(long)]
        no_guard: bool,
        /// Use the agentic tool loop (read/write/edit files, shell) instead of
        /// text proposals.
        #[arg(long)]
        agent: bool,
        /// Reasoning effort hint for providers that support it: low|medium|high.
        #[arg(long)]
        effort: Option<String>,
        /// Auto-approve tool calls unless the permission policy denies them.
        #[arg(long)]
        auto: bool,
        /// Plan mode: read-only, mutating tools are refused.
        #[arg(long)]
        plan: bool,
    },
    /// Manage API keys in the OS keychain.
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// Browse the OpenRouter model catalogue and pick a default.
    Models {
        /// Filter by substring (id or name).
        #[arg(short, long)]
        search: Option<String>,
        /// Set this model id as the default (validated against the catalogue).
        #[arg(short = 'S', long)]
        set: Option<String>,
        /// Max rows to display.
        #[arg(short, long, default_value = "30")]
        limit: usize,
        /// Show only free models.
        #[arg(long)]
        free: bool,
    },
    /// Show encrypted-database information (size, stats, encryption).
    Db,
    /// Manage encrypted sessions.
    Sessions {
        #[command(subcommand)]
        action: SessionsAction,
    },
    /// Manage the encrypted local memory (facts remembered across sessions).
    Memory {
        #[command(subcommand)]
        action: MemoryAction,
    },
    /// Show the encrypted egress ledger (what left the machine — fingerprints only).
    Ledger {
        /// Verify the tamper-evident hash chain instead of listing entries.
        #[arg(long)]
        verify: bool,
        /// Number of most-recent entries to show.
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },
    /// Show the resolved configuration (no secrets).
    Config,
    /// Securely delete the encrypted database, salt and stored keys.
    Wipe {
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum KeysAction {
    /// Store an API key.
    Set {
        provider: String,
        #[arg(short, long)]
        key: Option<String>,
        /// Store in the OS keychain instead of the local keys.toml file.
        #[arg(long)]
        keychain: bool,
    },
    /// Check whether an API key is present.
    Get { provider: String },
    /// Delete an API key.
    Delete { provider: String },
    /// List providers with a stored key.
    List,
}

#[derive(Subcommand, Debug)]
pub enum SessionsAction {
    /// List stored sessions.
    List,
    /// Show the stored messages of a session (defaults to the most recent).
    Show {
        /// Session id (omit for the most recent session that has messages).
        id: Option<String>,
    },
    /// Rename a session.
    Rename { id: String, name: String },
    /// Export a session to an encrypted file.
    Export { id: String, path: String },
    /// Import a session from an encrypted export file.
    Import { path: String },
    /// Delete a session by id (messages included).
    Delete {
        id: String,
        /// Also compact the database afterwards (removes deleted ciphertext).
        #[arg(long)]
        purge: bool,
    },
    /// Delete ALL sessions and compact the database.
    WipeAll {
        /// Skip the confirmation prompt.
        #[arg(long)]
        force: bool,
    },
    /// Compact the encrypted database (VACUUM).
    Vacuum,
}

#[derive(Subcommand, Debug)]
pub enum MemoryAction {
    /// Remember a new fact or preference.
    Add {
        text: String,
        /// Comma-separated tags (e.g. "prefs,editor").
        #[arg(short, long, default_value = "")]
        tags: String,
        /// Never send this memory to a remote provider.
        #[arg(long)]
        local_only: bool,
    },
    /// List stored memories (pinned first).
    List {
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },
    /// Search memories by substring (text or tags).
    Search { query: String },
    /// Pin or unpin a memory so it is always injected.
    Pin {
        id: String,
        /// Unpin instead of pinning.
        #[arg(long)]
        off: bool,
    },
    /// Edit a memory's text and/or tags.
    Edit {
        id: String,
        #[arg(short, long)]
        text: Option<String>,
        #[arg(short, long)]
        tags: Option<String>,
    },
    /// Delete a memory by id, or all memories matching a query.
    Forget {
        /// A memory id (or the full text of the memory to delete).
        what: String,
    },
    /// Delete every stored memory.
    Clear {
        #[arg(long)]
        force: bool,
    },
}

/// Entry point invoked by the binary.
pub fn run(cli: Cli) -> Result<()> {
    // Best-effort hardening: refuse core dumps so a crash cannot spill secrets.
    crate::privacy::secure::harden_process();
    let paths = Paths::resolve()?;
    paths.ensure_dirs()?;
    let mut settings = Settings::load(&paths.config_file)?;
    // Convenience override without editing config.toml.
    if let Ok(v) = std::env::var("ENCLAVE_USE_KEYCHAIN") {
        let v = v.trim().to_ascii_lowercase();
        settings.use_keychain = matches!(v.as_str(), "1" | "true" | "yes" | "on");
    }

    match cli.command {
        Command::Keys { action } => keys_cmd(action),
        Command::Sessions { action } => sessions_cmd(&paths, &settings, action),
        Command::Memory { action } => memory_cmd(&paths, &settings, action),
        Command::Ledger { verify, limit } => ledger_cmd(&paths, &settings, verify, limit),
        Command::Models {
            search,
            set,
            limit,
            free,
        } => {
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|e| EnclaveError::other(e.to_string()))?;
            runtime.block_on(models_cmd(&paths, search, set, limit, free))
        }
        Command::Db => db_cmd(&paths, &settings),
        Command::Config => {
            print_config(&paths, &settings);
            Ok(())
        }
        Command::Wipe { force } => wipe_cmd(&paths, force),
        Command::Chat {
            model,
            provider,
            session,
            no_keychain,
            no_tools,
            no_guard,
            agent,
            effort,
            attach,
            auto,
            plan,
        } => {
            let mut engine = build_engine(
                &paths,
                &settings,
                provider,
                model,
                session,
                no_keychain,
                effort,
                auto,
                plan,
            )?;
            let tools = settings.effective_tools(no_tools);
            let guard = settings.effective_guard(no_guard);
            engine.taint = guard.enabled && guard.taint;
            let agent_mode = (agent || tools.mode == crate::config::ToolsMode::Agent)
                && tools.enabled;
            let runner = if agent_mode {
                Some(std::sync::Arc::new(crate::core::AgentRunner::from_settings(&settings)))
            } else {
                None
            };
            let mut attachments = Vec::new();
            for path in &attach {
                match crate::core::Attachment::from_file(std::path::Path::new(path)) {
                    Ok(a) => attachments.push(a),
                    Err(e) => eprintln!("attach failed: {e}"),
                }
            }
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|e| EnclaveError::other(e.to_string()))?;
            runtime.block_on(chat_loop(engine, tools, guard, runner, attachments))
        }
        Command::Tui {
            model,
            provider,
            session,
            no_keychain,
            no_tools,
            no_guard,
            agent,
            effort,
            auto,
            plan,
        } => {
            let mut engine = build_engine(
                &paths,
                &settings,
                provider,
                model,
                session,
                no_keychain,
                effort,
                auto,
                plan,
            )?;
            let tools = settings.effective_tools(no_tools);
            let guard = settings.effective_guard(no_guard);
            engine.taint = guard.enabled && guard.taint;
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|e| EnclaveError::other(e.to_string()))?;
            runtime.block_on(crate::tui::run(engine, tools, guard, agent))
        }
    }
}

/// Obtain the master key, asking for the password only when needed.
///
/// With `use_keychain = true` (default) the derived key is cached in the local
/// credentials file (`keys.toml`, mode 0600) after the first unlock, so the
/// password is only required once and **no** OS-keychain dialog is shown. With
/// `use_keychain = false` the password is always required and nothing is stored.
fn unlock_master_key(vault: &Vault, settings: &Settings, no_keychain: bool) -> Result<MasterKey> {
    let use_keychain = settings.use_keychain && !no_keychain;
    if use_keychain {
        if let Some(key) = vault.try_cached_key() {
            return Ok(key);
        }
    }
    let password = rpassword::prompt_password("Master password: ")
        .map_err(|e| EnclaveError::other(e.to_string()))?;
    let kdf = settings
        .kdf
        .as_deref()
        .and_then(crate::privacy::crypto::Kdf::from_name)
        .unwrap_or(crate::privacy::crypto::Kdf::Argon2id);
    vault.derive_key_with(&password, use_keychain, kdf)
}

/// Unlock the master key for the interactive engine, honouring the duress
/// password: when `ENCLAVE_DURESS_PASSWORD` matches, a decoy vault is opened
/// instead (plausible deniability). Returns the key and the effective paths.
fn unlock_for_engine(
    paths: &Paths,
    settings: &Settings,
    no_keychain: bool,
) -> Result<(MasterKey, Paths)> {
    let use_keychain = settings.use_keychain && !no_keychain;
    let duress_on = crate::privacy::vault::duress_configured();
    let kdf = settings
        .kdf
        .as_deref()
        .and_then(crate::privacy::crypto::Kdf::from_name)
        .unwrap_or(crate::privacy::crypto::Kdf::Argon2id);

    // Fast path: cached key (only when no duress password is configured, since
    // duress requires seeing the typed password).
    if use_keychain && !duress_on {
        let vault = Vault::new(&paths.config_dir);
        if let Some(key) = vault.try_cached_key() {
            return Ok((key, paths.clone()));
        }
    }

    let password = rpassword::prompt_password("Master password: ")
        .map_err(|e| EnclaveError::other(e.to_string()))?;

    if crate::privacy::vault::duress_matches(&password) {
        // Open a decoy vault in its own directory; never touch the real one.
        let dir = paths.config_dir.join("decoy");
        std::fs::create_dir_all(&dir)?;
        let vault = Vault::new(&dir);
        let key = vault.derive_key_with(&password, false, kdf)?;
        let mut decoy = paths.clone();
        decoy.salt_path = dir.join("salt.bin");
        decoy.db_path = dir.join("vault.db");
        decoy.config_dir = dir;
        return Ok((key, decoy));
    }

    let vault = Vault::new(&paths.config_dir);
    let key = vault.derive_key_with(&password, use_keychain, kdf)?;
    Ok((key, paths.clone()))
}

#[allow(clippy::too_many_arguments)]
fn build_engine(
    paths: &Paths,
    settings: &Settings,
    provider_name: Option<String>,
    model: Option<String>,
    session_id: Option<String>,
    no_keychain: bool,
    effort: Option<String>,
    auto: bool,
    plan: bool,
) -> Result<ChatEngine> {
    let provider_name = provider_name.unwrap_or_else(|| settings.default_provider.clone());

    let (key, effective) = unlock_for_engine(paths, settings, no_keychain)?;

    let memory = EncryptedMemory::open(&effective.db_path, &key)?;
    let session = match session_id {
        Some(id) => Session::load(&memory, &id)?,
        // Prefer the explicitly remembered working session, then the most
        // recently used session that actually has messages (so empty throwaway
        // sessions are skipped and past conversations come back).
        None => {
            let resumed = settings
                .working_session
                .as_ref()
                .filter(|id| memory.session_exists(id).unwrap_or(false))
                .cloned();
            match resumed {
                Some(id) => Session::load(&memory, &id)?,
                None => match memory
                    .list_sessions()?
                    .into_iter()
                    .find(|info| info.message_count > 0)
                {
                    Some(info) => Session::load(&memory, &info.id)?,
                    None => Session::create(&memory, "chat")?,
                },
            }
        }
    };

    // Honour the saved default model when the provider matches; an explicit
    // --model always wins, and a different provider falls back to its own
    // default (the saved model likely belongs to another provider).
    let model = model.or_else(|| {
        if provider_name == settings.default_provider {
            Some(settings.default_model.clone())
        } else {
            None
        }
    });

    // The provider (and therefore the API key in the keychain) is created
    // lazily on the first message — no keychain dialog at startup.
    let mut engine = ChatEngine::lazy(
        &provider_name,
        settings.ollama_base_url.clone(),
        model,
        memory,
        session,
        settings.system_prompt.clone(),
    )?;
    engine.reasoning_effort = effort.or_else(|| settings.reasoning_effort.clone());

    // Local AGENTS.md rules + permission policy + operating mode.
    let cwd = std::env::current_dir().unwrap_or_default();
    engine.workspace = cwd.clone();
    engine.rules = crate::core::rules::load(&cwd, &paths.config_dir, &settings.instructions);
    engine.permissions = settings.permissions.clone();
    if auto {
        engine.permissions.auto = true;
    }
    if plan {
        engine.mode = crate::core::engine::AgentMode::Plan;
    }
    engine.mcp = crate::core::mcp::McpRegistry::connect_all(&settings.mcp)
        .map(std::sync::Arc::new);
    engine.policy = crate::privacy::policy::Policy::from_settings(&settings.policy);
    engine.reload_memories()?;
    persist_working_session(paths, &engine.session.id);
    Ok(engine)
}

/// Remember the session that is "in work" so the next launch resumes it.
fn persist_working_session(paths: &Paths, id: &str) {
    if let Ok(mut s) = Settings::load(&paths.config_file) {
        if s.working_session.as_deref() != Some(id) {
            s.working_session = Some(id.to_string());
            let _ = s.save(&paths.config_file);
        }
    }
}

/// Session-scoped privacy-guard decision (never persisted).
enum GuardDecision {
    /// No sensitive data seen yet.
    Undecided,
    /// User chose "send as-is" for this session.
    Approved,
    /// Placeholders are active (redactor lives in the engine).
    Redacted,
}

async fn chat_loop(
    mut engine: ChatEngine,
    tools: crate::config::ToolsSettings,
    guard: crate::config::GuardSettings,
    runner: Option<std::sync::Arc<crate::core::AgentRunner>>,
    mut attachments: Vec<crate::core::Attachment>,
) -> Result<()> {
    use futures::StreamExt;

    println!(
        "Enclave — provider: {}, model: {}, session: {}",
        engine.provider_name(),
        engine.model,
        engine.session.id
    );
    if tools.enabled {
        if runner.is_some() {
            println!("Tools: ON (agentic) — function calling with read_file/write_file/list_dir/run_shell; every call needs your approval.");
        } else {
            println!("Tools: ON — the assistant may propose shell commands; nothing runs without your approval.");
        }
    }
    if guard.enabled {
        println!(
            "Privacy guard: ON ({}) — sensitive data is detected before anything leaves the machine.",
            match guard.mode {
                crate::config::GuardMode::Ask => "ask",
                crate::config::GuardMode::Redact => "auto-placeholder",
                crate::config::GuardMode::Block => "block",
            }
        );
    }
    println!("Type 'exit' to quit, 'clear' to start a fresh session.\n");

    let mut decision = GuardDecision::Undecided;

    loop {
        print!("you> ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        let read = std::io::stdin().read_line(&mut line)?;
        if read == 0 {
            println!();
            break;
        }
        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        if matches!(input, "exit" | "quit" | ":q") {
            break;
        }
        if input == "clear" {
            engine.session.clear(&engine.memory)?;
            println!("session cleared\n");
            continue;
        }

        // `!command`: run it locally; the output is never sent to the model.
        if let Some(cmd) = input.strip_prefix('!') {
            let cmd = cmd.trim();
            if cmd.is_empty() {
                println!("usage: !<shell command>\n");
            } else {
                match crate::core::tools::run_sandboxed(
                    cmd,
                    std::time::Duration::from_secs(tools.timeout_secs),
                    tools.max_output_bytes,
                    Some(&crate::core::tools::Sandbox::new(
                        tools.sandbox,
                        std::env::current_dir().unwrap_or_default(),
                    )),
                )
                .await
                {
                    Ok(out) => println!("{}\n", out.render()),
                    Err(e) => println!("error: {e}\n"),
                }
            }
            continue;
        }

        // `@file` references become attachments (local, guarded like text).
        let workspace = std::env::current_dir().unwrap_or_default();
        let resolved = crate::core::commands::resolve_file_refs(input, &workspace);
        if !resolved.names.is_empty() {
            println!("attached: {}", resolved.names.join(", "));
        }
        attachments.extend(resolved.attachments);
        let input = resolved.text;
        let input = input.as_str();

        if !guard_gate(&mut engine, &mut decision, input, &guard)? {
            println!("message not sent\n");
            continue;
        }

        match &runner {
            Some(runner) => {
                let defs = runner.defs();
                let ctx = runner.context();
                let mut gate = CliGate::new();
                print!("ai> ");
                std::io::stdout().flush().ok();
                match engine
                    .turn_agentic_with(
                        input,
                        std::mem::take(&mut attachments),
                        &defs,
                        &ctx,
                        &mut gate,
                        8,
                    )
                    .await
                {
                    Ok(text) if !text.is_empty() => println!("{text}\n"),
                    Ok(_) => {}
                    Err(e) => println!("error: {e}"),
                }
            }
            None => {
                print!("ai> ");
                std::io::stdout().flush().ok();
                let mut stream = engine
                    .stream_reply_with(input, std::mem::take(&mut attachments))
                    .await?;
                let mut full = String::new();
                while let Some(chunk) = stream.next().await {
                    let piece = chunk?;
                    print!("{piece}");
                    std::io::stdout().flush().ok();
                    full.push_str(&piece);
                }
                println!();
                engine.commit_assistant(full.clone())?;
                handle_proposals(&mut engine, &full, &tools).await?;
            }
        }
    }

    Ok(())
}

/// Interactive approval gate for the agentic loop (ask-always).
struct CliGate {
    approve_all: bool,
}

impl CliGate {
    fn new() -> Self {
        Self { approve_all: false }
    }
}

#[async_trait::async_trait]
impl crate::core::engine::ToolGate for CliGate {
    async fn decide(&mut self, call: &crate::core::ToolCall) -> crate::core::engine::ToolDecision {
        use crate::core::engine::ToolDecision;

        if self.approve_all {
            return ToolDecision::ApproveAll;
        }
        println!("— proposed tool call —");
        println!("  tool: {}", call.name);
        match serde_json::from_str::<serde_json::Value>(&call.arguments) {
            Ok(v) => println!("  args: {}", serde_json::to_string_pretty(&v).unwrap_or_default()),
            Err(_) => println!("  args: {}", call.arguments),
        }
        let answer = prompt_run_choice().unwrap_or_default();
        match answer.as_str() {
            "a" => {
                self.approve_all = true;
                ToolDecision::ApproveAll
            }
            "y" => ToolDecision::Approve,
            "q" => ToolDecision::Stop,
            _ => ToolDecision::Deny,
        }
    }

    async fn observe(&mut self, call: &crate::core::ToolCall, output: &str) {
        println!("[{}] {}", call.name, output.trim_end());
    }
}

/// Privacy-guard gate: scan the input and enforce the configured behaviour.
///
/// Returns `true` when the message may be sent.
fn guard_gate(
    engine: &mut ChatEngine,
    decision: &mut GuardDecision,
    input: &str,
    guard: &crate::config::GuardSettings,
) -> Result<bool> {
    use crate::config::GuardMode;
    use crate::privacy::guard::{self, Redactor};

    if !guard.enabled {
        return Ok(true);
    }
    let findings = guard::scan(input);

    match decision {
        GuardDecision::Approved => return Ok(true),
        GuardDecision::Redacted => return Ok(true), // engine.redactor handles everything
        GuardDecision::Undecided => {}
    }

    if findings.is_empty() {
        return Ok(true);
    }

    match guard.mode {
        GuardMode::Redact => {
            engine.redactor = Some(Redactor::new());
            *decision = GuardDecision::Redacted;
            println!(
                "privacy guard: {} sensitive item(s) replaced with placeholders",
                findings.len()
            );
            Ok(true)
        }
        GuardMode::Block => {
            print_findings(&findings);
            println!("blocked by privacy guard (mode: block) — message not sent");
            Ok(false)
        }
        GuardMode::Ask => {
            print_findings(&findings);
            let answer = prompt_guard_choice()?;
            match answer.as_str() {
                "s" => {
                    *decision = GuardDecision::Approved;
                    println!("privacy guard: off for this session");
                    Ok(true)
                }
                "p" => {
                    engine.redactor = Some(Redactor::new());
                    *decision = GuardDecision::Redacted;
                    println!("privacy guard: placeholders active for this session");
                    Ok(true)
                }
                _ => Ok(false),
            }
        }
    }
}

fn print_findings(findings: &[crate::privacy::guard::Finding]) {
    println!(
        "⚠ privacy guard — {} sensitive item(s) detected:",
        findings.len()
    );
    for f in findings {
        println!("  · {}: {}", f.kind.label(), f.text);
    }
}

fn prompt_guard_choice() -> Result<String> {
    print!("send [s]as-is / [p]laceholders / [r]efuse > ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    let n = std::io::stdin().read_line(&mut line)?;
    if n == 0 {
        // EOF: refuse (privacy-first).
        return Ok("r".to_string());
    }
    Ok(line.trim().to_lowercase())
}

/// Offer the assistant's shell proposals for execution (ask-always).
async fn handle_proposals(
    engine: &mut ChatEngine,
    reply: &str,
    tools: &crate::config::ToolsSettings,
) -> Result<()> {
    use crate::core::tools;

    if !tools.enabled {
        return Ok(());
    }
    let proposals = tools::extract_proposals(reply);
    if proposals.is_empty() {
        return Ok(());
    }

    println!(
        "— the assistant proposed {} shell command(s); nothing runs without your approval —",
        proposals.len()
    );
    let mut approve_all = false;
    for p in &proposals {
        println!("$ {}", p.command);
        let answer = if approve_all {
            "a".to_string()
        } else {
            prompt_run_choice()?
        };
        match answer.as_str() {
            "q" => {
                println!("skipped remaining proposals");
                break;
            }
            "a" => {
                approve_all = true;
                run_proposal(engine, p, tools).await?;
            }
            "y" => run_proposal(engine, p, tools).await?,
            _ => println!("skipped"),
        }
    }
    Ok(())
}

async fn run_proposal(
    engine: &mut ChatEngine,
    proposal: &crate::core::tools::Proposal,
    tools: &crate::config::ToolsSettings,
) -> Result<()> {
    let timeout = std::time::Duration::from_secs(tools.timeout_secs.max(1));
    let sandbox = crate::core::tools::Sandbox::new(
        tools.sandbox,
        std::env::current_dir().unwrap_or_default(),
    );
    let output = crate::core::tools::run_sandboxed(
        &proposal.command,
        timeout,
        tools.max_output_bytes,
        Some(&sandbox),
    )
    .await?;
    println!("{}", output.render());

    // Feed the result back into the conversation (encrypted at rest; it will
    // travel to the provider on the next turn — see docs/privacy.md).
    engine
        .session
        .add_user(&engine.memory, &output.as_tool_message(&proposal.command))?;
    Ok(())
}

fn prompt_run_choice() -> Result<String> {
    print!("run? [y]es / [n]o / [a]ll / [q]uit > ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    let n = std::io::stdin().read_line(&mut line)?;
    if n == 0 {
        // EOF: never execute.
        return Ok("n".to_string());
    }
    Ok(line.trim().to_lowercase())
}

/// Ask the user a free-form question on behalf of the model (`question` tool).
pub fn prompt_question(question: &str, options: &[String]) -> Result<String> {
    println!("\n? {question}");
    for (i, o) in options.iter().enumerate() {
        println!("  {}. {o}", i + 1);
    }
    print!("your answer: ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    let n = std::io::stdin().read_line(&mut line)?;
    if n == 0 {
        return Ok("[no answer given]".to_string());
    }
    let answer = line.trim().to_string();
    if answer.is_empty() {
        return Ok("[no answer given]".to_string());
    }
    Ok(answer)
}

fn keys_cmd(action: KeysAction) -> Result<()> {
    match action {
        KeysAction::Set {
            provider,
            key,
            keychain,
        } => {
            let key = match key {
                Some(k) => k,
                None => rpassword::prompt_password(format!("API key for {provider}: "))
                    .map_err(|e| EnclaveError::other(e.to_string()))?,
            };
            if keychain {
                SecureCredentials::store(&provider, key.trim())?;
                println!("stored API key for '{provider}' in the OS keychain");
            } else {
                SecureCredentials::store_file(&provider, key.trim())?;
                let path = SecureCredentials::keys_path()?;
                println!(
                    "stored API key for '{provider}' in {} (mode 0600, no keychain prompts)",
                    path.display()
                );
            }
            Ok(())
        }
        KeysAction::Get { provider } => {
            if let Some(source) = SecureCredentials::source(&provider) {
                let preview = SecureCredentials::local_api_key(&provider)
                    .map(|k| k.chars().take(8).collect::<String>())
                    .unwrap_or_default();
                if preview.is_empty() {
                    println!("key for '{provider}' provided by {source}");
                } else {
                    println!("key for '{provider}' provided by {source} (starts with {preview}…)");
                }
                return Ok(());
            }
            // Not in env/file: fall back to the keychain (may prompt once).
            match SecureCredentials::get(&provider) {
                Ok(k) => {
                    let preview: String = k.chars().take(8).collect();
                    if SecureCredentials::store_file(&provider, &k).is_ok() {
                        println!(
                            "migrated key for '{provider}' from the OS keychain to keys.toml \
                             (starts with {preview}…) — no more prompts"
                        );
                    } else {
                        println!("key for '{provider}' present in the OS keychain (starts with {preview}…)");
                    }
                    Ok(())
                }
                Err(_) => {
                    println!("no key stored for '{provider}'. Run: enclave keys set {provider}");
                    Ok(())
                }
            }
        }
        KeysAction::Delete { provider } => {
            SecureCredentials::delete_file(&provider)?;
            let _ = SecureCredentials::delete(&provider);
            println!("deleted key for '{provider}' (local file and keychain)");
            Ok(())
        }
        KeysAction::List => {
            let configured = SecureCredentials::configured(known_providers());
            if configured.is_empty() {
                println!("no providers configured. Run: enclave keys set <provider>");
            } else {
                println!("configured providers:");
                for p in configured {
                    let src = SecureCredentials::source(&p).unwrap_or_default();
                    println!("  • {p}  ({src})");
                }
            }
            Ok(())
        }
    }
}

/// Fetch the OpenRouter catalogue and render it (or set the default model).
async fn models_cmd(
    paths: &Paths,
    search: Option<String>,
    set: Option<String>,
    limit: usize,
    free_only: bool,
) -> Result<()> {
    use crate::providers::OpenRouterModel;

    let models = OpenRouterModel::fetch_all().await?;
    if models.is_empty() {
        return Err(EnclaveError::provider("empty model catalogue from openrouter"));
    }

    let needle = search.map(|s| s.to_lowercase());
    let filtered: Vec<&OpenRouterModel> = models
        .iter()
        .filter(|m| !free_only || m.is_free())
        .filter(|m| match &needle {
            Some(n) => m.id.to_lowercase().contains(n) || m.name.to_lowercase().contains(n),
            None => true,
        })
        .collect();

    if filtered.is_empty() {
        println!("no models match your filters");
        return Ok(());
    }

    if let Some(model_id) = set {
        if !filtered.iter().any(|m| m.id == model_id) {
            return Err(EnclaveError::provider(format!(
                "model '{model_id}' not in catalogue — pick an exact id from the table"
            )));
        }
        let mut settings = Settings::load(&paths.config_file)?;
        settings.default_model = model_id.clone();
        settings.save(&paths.config_file)?;
        println!("default model saved: {model_id}");
        println!("config: {}", paths.config_file.display());
        return Ok(());
    }

    println!(
        "{} models match (showing up to {limit}, use --search / --free / --limit)  ·  set one with --set <id>",
        filtered.len()
    );
    println!(
        "{:<44} {:<30} {:>8}  {:>10}  {:>10}",
        "MODEL ID", "NAME", "CTX", "$PROMPT/M", "$COMPL/M"
    );
    for m in filtered.iter().take(limit) {
        let name: String = if m.name.chars().count() > 30 {
            m.name.chars().take(29).collect::<String>() + "…"
        } else {
            m.name.clone()
        };
        let (p, c) = if m.is_free() {
            ("FREE".to_string(), String::new())
        } else {
            (format!("{:.3}", m.prompt_price), format!("{:.3}", m.completion_price))
        };
        println!(
            "{:<44} {:<30} {:>8}  {:>10}  {:>10}",
            m.id,
            name,
            m.context_length,
            p,
            c
        );
    }
    Ok(())
}

/// Show encrypted-database information.
fn db_cmd(paths: &Paths, settings: &Settings) -> Result<()> {
    use crate::privacy::EncryptedMemory;

    let vault = Vault::new(&paths.config_dir);
    let key = unlock_master_key(&vault, settings, false)?;
    let memory = EncryptedMemory::open(&paths.db_path, &key)?;
    let stats = memory.stats()?;

    let file_size = std::fs::metadata(&paths.db_path).map(|m| m.len()).unwrap_or(0);
    let fmt_size = |bytes: u64| -> String {
        if bytes >= 1_048_576 {
            format!("{:.1} MB", bytes as f64 / 1_048_576.0)
        } else if bytes >= 1024 {
            format!("{:.1} KB", bytes as f64 / 1024.0)
        } else {
            format!("{bytes} B")
        }
    };

    let computed = stats.page_size as u64 * stats.page_count as u64;
    println!("Enclave encrypted database");
    println!("  file         : {}", paths.db_path.display());
    println!("  size on disk : {}", fmt_size(file_size));
    println!("  encryption   : SQLCipher AES-256 (page {} B, {} pages)", stats.page_size, stats.page_count);
    println!("  freed pages  : {} ({} — run 'enclave sessions vacuum' to reclaim)", stats.freelist_count, fmt_size(stats.freelist_count as u64 * stats.page_size as u64));
    println!("  computed     : {}", fmt_size(computed));
    println!("  sessions     : {}", stats.sessions);
    println!("  messages     : {}", stats.messages);
    println!(
        "  key store    : {}",
        if settings.use_keychain {
            "local keys.toml (0600) — password asked once"
        } else {
            "password every launch (nothing stored)"
        }
    );
    Ok(())
}

fn memory_cmd(paths: &Paths, settings: &Settings, action: MemoryAction) -> Result<()> {
    use crate::privacy::EncryptedMemory;

    let vault = Vault::new(&paths.config_dir);
    let key = unlock_master_key(&vault, settings, false)?;
    let memory = EncryptedMemory::open(&paths.db_path, &key)?;

    let short = |id: &str| id[..8.min(id.len())].to_string();

    match action {
        MemoryAction::Add {
            text,
            tags,
            local_only,
        } => {
            let text = text.trim();
            if text.is_empty() {
                return Err(EnclaveError::other("memory text cannot be empty"));
            }
            let id = memory.add_memory(text, tags.trim(), "note", None, local_only)?;
            println!(
                "remembered [{}]{}{}",
                short(&id),
                if local_only { " (local-only)" } else { "" },
                text
            );
        }
        MemoryAction::List { limit } => {
            let mems = memory.list_memories(limit)?;
            if mems.is_empty() {
                println!("no memories stored (add one with: enclave memory add \"...\")");
            } else {
                for m in mems {
                    println!("{}  {}{}{}", short(&m.id), m.text, tags_suffix(&m.tags), flags_suffix(m.pinned, m.local_only));
                }
                println!("\n{} memories", memory.memory_count()?);
            }
        }
        MemoryAction::Search { query } => {
            let mems = memory.search_memories(&query, 100)?;
            if mems.is_empty() {
                println!("no memories match '{query}'");
            } else {
                for m in mems {
                    println!("{}  {}{}{}", short(&m.id), m.text, tags_suffix(&m.tags), flags_suffix(m.pinned, m.local_only));
                }
            }
        }
        MemoryAction::Pin { id, off } => {
            if memory.set_memory_pinned(&id, !off)? {
                println!("{} [{}]", if off { "unpinned" } else { "pinned" }, short(&id));
            } else {
                println!("no memory with id '{id}'");
            }
        }
        MemoryAction::Edit { id, text, tags } => {
            let cur = memory
                .get_memory(&id)?
                .ok_or_else(|| EnclaveError::other(format!("no memory with id '{id}'")))?;
            let new_text = text.unwrap_or(cur.text);
            let new_tags = tags.unwrap_or(cur.tags);
            if memory.update_memory(&id, &new_text, &new_tags)? {
                println!("updated [{}]", short(&id));
            }
        }
        MemoryAction::Forget { what } => {
            if memory.delete_memory(&what)? {
                println!("forgot [{}]", short(&what));
            } else {
                let n = memory.delete_memories_matching(&what)?;
                if n == 0 {
                    println!("no memory matched '{what}'");
                } else {
                    println!("forgot {n} memor{} matching '{what}'", if n == 1 { "y" } else { "ies" });
                }
            }
        }
        MemoryAction::Clear { force } => {
            if !force {
                print!("delete ALL memories? [y/N] ");
                use std::io::Write;
                std::io::stdout().flush().ok();
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).ok();
                if !line.trim().eq_ignore_ascii_case("y") {
                    println!("aborted");
                    return Ok(());
                }
            }
            let n = memory.delete_memories_matching("")?;
            println!("deleted {n} memor{}", if n == 1 { "y" } else { "ies" });
        }
    }
    Ok(())
}

/// Show or verify the encrypted egress ledger.
fn ledger_cmd(paths: &Paths, settings: &Settings, verify: bool, limit: usize) -> Result<()> {
    let vault = Vault::new(&paths.config_dir);
    let key = unlock_master_key(&vault, settings, false)?;
    let memory = EncryptedMemory::open(&paths.db_path, &key)?;

    if verify {
        let ok = memory.verify_egress_chain()?;
        if ok {
            println!(
                "egress ledger: chain OK ({} entries, none tampered)",
                memory.egress_count()?
            );
        } else {
            println!("egress ledger: CHAIN BROKEN — the ledger was modified");
            std::process::exit(2);
        }
        return Ok(());
    }

    let entries = memory.list_egress(limit)?;
    if entries.is_empty() {
        println!("egress ledger is empty (nothing has been sent yet)");
        return Ok(());
    }
    println!(
        "egress ledger ({} total, showing {} most recent):",
        memory.egress_count()?,
        entries.len()
    );
    for e in entries {
        let red = if e.redactions.is_empty() {
            String::new()
        } else {
            format!("  redacted: {}", e.redactions)
        };
        println!(
            "#{:<5} {}  {} · {}  {} bytes  sha {}{}",
            e.id,
            e.ts,
            e.provider,
            e.model,
            e.payload_bytes,
            &e.payload_sha[..12.min(e.payload_sha.len())],
            red
        );
    }
    println!("\nthe ledger stores fingerprints only — never payloads or secrets");
    Ok(())
}

fn tags_suffix(tags: &str) -> String {
    if tags.trim().is_empty() {
        String::new()
    } else {
        format!("  #{}", tags.trim().replace(',', " #"))
    }
}

fn flags_suffix(pinned: bool, local_only: bool) -> String {
    let mut marks = Vec::new();
    if pinned {
        marks.push("pinned");
    }
    if local_only {
        marks.push("local-only");
    }
    if marks.is_empty() {
        String::new()
    } else {
        format!("  [{}]", marks.join(","))
    }
}

fn sessions_cmd(paths: &Paths, settings: &Settings, action: SessionsAction) -> Result<()> {
    let vault = Vault::new(&paths.config_dir);
    let key = unlock_master_key(&vault, settings, false)?;
    let memory = EncryptedMemory::open(&paths.db_path, &key)?;

    match action {
        SessionsAction::List => {
            let sessions = memory.list_sessions()?;
            if sessions.is_empty() {
                println!("no sessions stored");
            } else {
                for s in sessions {
                    println!("{}  {}  ({} messages, {})", s.id, s.name, s.message_count, s.updated_at);
                }
            }
            Ok(())
        }
        SessionsAction::Show { id } => {
            let sessions = memory.list_sessions()?;
            let sid = match id {
                Some(id) => id,
                None => sessions
                    .iter()
                    .find(|s| s.message_count > 0)
                    .map(|s| s.id.clone())
                    .ok_or_else(|| EnclaveError::other("no session has messages yet"))?,
            };
            let name = sessions
                .iter()
                .find(|s| s.id == sid)
                .map(|s| s.name.clone())
                .unwrap_or_else(|| "?".into());
            let history = memory.get_history(&sid, 100_000)?;
            println!("session {sid} '{name}' — {} messages", history.len());
            for (i, m) in history.iter().enumerate() {
                let role = m.role.as_str();
                if m.tool_calls.is_empty() {
                    println!("{:>3}. {role}: {}", i + 1, m.content.trim());
                } else {
                    let names: Vec<&str> = m.tool_calls.iter().map(|c| c.name.as_str()).collect();
                    println!(
                        "{:>3}. {role}: [tool calls: {}] {}",
                        i + 1,
                        names.join(", "),
                        m.content.trim()
                    );
                }
            }
            Ok(())
        }
        SessionsAction::Rename { id, name } => {
            memory.rename_session(&id, &name)?;
            println!("renamed session '{id}' to '{name}'");
            Ok(())
        }
        SessionsAction::Export { id, path } => {
            let pass = rpassword::prompt_password("Export password: ")
                .map_err(|e| EnclaveError::other(e.to_string()))?;
            let confirm = rpassword::prompt_password("Confirm export password: ")
                .map_err(|e| EnclaveError::other(e.to_string()))?;
            if pass != confirm {
                return Err(EnclaveError::other("passwords do not match"));
            }
            let count = crate::privacy::export::export_session(
                &memory,
                &id,
                std::path::Path::new(&path),
                &pass,
            )?;
            println!(
                "exported {count} messages to '{}' (encrypted)",
                path
            );
            Ok(())
        }
        SessionsAction::Import { path } => {
            let pass = rpassword::prompt_password("Export password: ")
                .map_err(|e| EnclaveError::other(e.to_string()))?;
            let (new_id, count) = crate::privacy::export::import_session(
                &memory,
                std::path::Path::new(&path),
                &pass,
            )?;
            println!("imported {count} messages as new session '{new_id}'");
            Ok(())
        }
        SessionsAction::Delete { id, purge } => {
            memory.delete_session(&id)?;
            println!("deleted session '{id}'");
            if purge {
                memory.vacuum()?;
                println!("database compacted (freed ciphertext removed)");
            }
            Ok(())
        }
        SessionsAction::WipeAll { force } => {
            if !force {
                print!("Delete ALL sessions and their messages? This cannot be undone [y/N] ");
                std::io::stdout().flush().ok();
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
                    println!("aborted");
                    return Ok(());
                }
            }
            let n = memory.delete_all_sessions()?;
            memory.vacuum()?;
            println!("deleted {n} session(s); database compacted");
            Ok(())
        }
        SessionsAction::Vacuum => {
            let before = std::fs::metadata(&paths.db_path).map(|m| m.len()).unwrap_or(0);
            memory.vacuum()?;
            let after = std::fs::metadata(&paths.db_path).map(|m| m.len()).unwrap_or(0);
            println!(
                "database compacted: {} → {} bytes",
                before, after
            );
            Ok(())
        }
    }
}

fn print_config(paths: &Paths, settings: &Settings) {
    println!("Enclave configuration");
    println!("  config dir : {}", paths.config_dir.display());
    println!("  data dir   : {}", paths.data_dir.display());
    println!("  database   : {}", paths.db_path.display());
    println!("  encryption : AES-256 (SQLCipher, PBKDF2-HMAC-SHA256 600k)");
    println!("  key store  : OS keychain");
    println!(
        "  tools      : {} (ask-always, timeout {}s, output cap {}B)",
        if settings.tools.enabled { "enabled" } else { "disabled" },
        settings.tools.timeout_secs,
        settings.tools.max_output_bytes
    );
    println!("  telemetry  : DISABLED");
}

fn wipe_cmd(paths: &Paths, force: bool) -> Result<()> {
    if !force {
        print!("Delete ALL encrypted data and stored keys? This cannot be undone [y/N] ");
        std::io::stdout().flush().ok();
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("aborted");
            return Ok(());
        }
    }

    for path in [&paths.db_path, &paths.salt_path, &paths.config_file] {
        if path.exists() {
            std::fs::remove_file(path)?;
            println!("removed {}", path.display());
        }
    }

    let _ = SecureCredentials::delete_file_store();
    for provider in known_providers() {
        let _ = SecureCredentials::delete(provider);
    }
    let _ = SecureCredentials::delete_master_key();

    println!("all data wiped");
    Ok(())
}

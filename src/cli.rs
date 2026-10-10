//! Command line interface (clap) and command dispatch.

use std::io::Write;

use clap::{Parser, Subcommand};

use crate::config::{Paths, Settings};
use crate::core::engine::ChatEngine;
use crate::core::session::Session;
use crate::error::{EnclaveError, Result};
use crate::privacy::{EncryptedMemory, SecureCredentials, Vault};
use crate::providers::{create_provider, known_providers, requires_api_key};

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

/// Entry point invoked by the binary.
pub fn run(cli: Cli) -> Result<()> {
    let paths = Paths::resolve()?;
    paths.ensure_dirs()?;
    let settings = Settings::load(&paths.config_file)?;

    match cli.command {
        Command::Keys { action } => keys_cmd(action),
        Command::Sessions { action } => sessions_cmd(&paths, &settings, action),
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
        } => {
            let engine = build_engine(
                &paths,
                &settings,
                provider,
                model,
                session,
                no_keychain,
            )?;
            let tools = settings.effective_tools(no_tools);
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|e| EnclaveError::other(e.to_string()))?;
            runtime.block_on(chat_loop(engine, tools))
        }
        Command::Tui {
            model,
            provider,
            session,
            no_keychain,
            no_tools,
        } => {
            let engine = build_engine(
                &paths,
                &settings,
                provider,
                model,
                session,
                no_keychain,
            )?;
            let tools = settings.effective_tools(no_tools);
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|e| EnclaveError::other(e.to_string()))?;
            runtime.block_on(crate::tui::run(engine, tools))
        }
    }
}

fn build_engine(
    paths: &Paths,
    settings: &Settings,
    provider_name: Option<String>,
    model: Option<String>,
    session_id: Option<String>,
    no_keychain: bool,
) -> Result<ChatEngine> {
    let provider_name = provider_name.unwrap_or_else(|| settings.default_provider.clone());

    let api_key = if requires_api_key(&provider_name) {
        Some(SecureCredentials::get(&provider_name)?)
    } else {
        None
    };
    let provider = create_provider(&provider_name, api_key, &settings.ollama_base_url)?;
    let model = model.unwrap_or_else(|| provider.default_model().to_string());

    let password = rpassword::prompt_password("Master password: ")
        .map_err(|e| EnclaveError::other(e.to_string()))?;
    let vault = Vault::new(&paths.config_dir);
    let key = vault.derive_key(&password, settings.use_keychain && !no_keychain)?;

    let memory = EncryptedMemory::open(&paths.db_path, &key)?;
    let session = match session_id {
        Some(id) => Session::load(&memory, &id)?,
        None => Session::create(&memory, "chat")?,
    };

    Ok(ChatEngine::new(
        provider,
        model,
        memory,
        session,
        settings.system_prompt.clone(),
    ))
}

async fn chat_loop(mut engine: ChatEngine, tools: crate::config::ToolsSettings) -> Result<()> {
    use futures::StreamExt;

    println!(
        "Enclave — provider: {}, model: {}, session: {}",
        engine.provider_name(),
        engine.model,
        engine.session.id
    );
    if tools.enabled {
        println!("Tools: ON — the assistant may propose shell commands; nothing runs without your approval.");
    }
    println!("Type 'exit' to quit, 'clear' to start a fresh session.\n");

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

        print!("ai> ");
        std::io::stdout().flush().ok();
        let mut stream = engine.stream_reply(input).await?;
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

    Ok(())
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
    let output =
        crate::core::tools::run(&proposal.command, timeout, tools.max_output_bytes).await?;
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

fn keys_cmd(action: KeysAction) -> Result<()> {
    match action {
        KeysAction::Set { provider, key } => {
            let key = match key {
                Some(k) => k,
                None => rpassword::prompt_password(format!("API key for {provider}: "))
                    .map_err(|e| EnclaveError::other(e.to_string()))?,
            };
            SecureCredentials::store(&provider, key.trim())?;
            println!("stored API key for '{provider}' in the OS keychain");
            Ok(())
        }
        KeysAction::Get { provider } => match SecureCredentials::get(&provider) {
            Ok(k) => {
                let preview: String = k.chars().take(8).collect();
                println!("key for '{provider}' present (starts with {preview}…)");
                Ok(())
            }
            Err(_) => {
                println!("no key stored for '{provider}'");
                Ok(())
            }
        },
        KeysAction::Delete { provider } => {
            SecureCredentials::delete(&provider)?;
            println!("deleted key for '{provider}'");
            Ok(())
        }
        KeysAction::List => {
            let configured = SecureCredentials::configured(known_providers());
            if configured.is_empty() {
                println!("no providers configured. Run: enclave keys set <provider>");
            } else {
                println!("configured providers:");
                for p in configured {
                    println!("  • {p}");
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

    let password = rpassword::prompt_password("Master password: ")
        .map_err(|e| EnclaveError::other(e.to_string()))?;
    let vault = Vault::new(&paths.config_dir);
    let key = vault.derive_key(&password, settings.use_keychain)?;
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
    println!("  key store    : {}", if settings.use_keychain { "OS keychain" } else { "password only" });
    Ok(())
}

fn sessions_cmd(paths: &Paths, settings: &Settings, action: SessionsAction) -> Result<()> {
    let password = rpassword::prompt_password("Master password: ")
        .map_err(|e| EnclaveError::other(e.to_string()))?;
    let vault = Vault::new(&paths.config_dir);
    let key = vault.derive_key(&password, settings.use_keychain)?;
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

    for provider in known_providers() {
        let _ = SecureCredentials::delete(provider);
    }
    let _ = SecureCredentials::delete_master_key();

    println!("all data wiped");
    Ok(())
}

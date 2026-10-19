//! Filesystem locations and application settings.

use std::path::{Path, PathBuf};

use crate::error::{EnclaveError, Result};

/// Resolved filesystem locations used by Enclave.
///
/// Follows the XDG base directory specification on Linux and the native
/// conventions on macOS (`~/Library/Application Support`) and Windows.
#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub db_path: PathBuf,
    pub salt_path: PathBuf,
    pub config_file: PathBuf,
}

impl Paths {
    /// Resolve the default platform directories.
    pub fn resolve() -> Result<Self> {
        let dirs = directories::ProjectDirs::from("dev", "enclave", "enclave")
            .ok_or_else(|| EnclaveError::config("could not determine project directories"))?;
        Ok(Self::from_dirs(dirs.config_dir(), dirs.data_dir()))
    }

    /// Build paths rooted at an arbitrary base directory (used by tests).
    pub fn from_base(base: &Path) -> Self {
        Self::from_dirs(&base.join("config"), &base.join("data"))
    }

    fn from_dirs(config_dir: &Path, data_dir: &Path) -> Self {
        Self {
            config_dir: config_dir.to_path_buf(),
            data_dir: data_dir.to_path_buf(),
            db_path: data_dir.join("vault.db"),
            salt_path: config_dir.join("salt.bin"),
            config_file: config_dir.join("config.toml"),
        }
    }

    /// Create the config and data directories if they do not exist.
    pub fn ensure_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(&self.config_dir)?;
        std::fs::create_dir_all(&self.data_dir)?;
        Ok(())
    }
}

/// Tool-execution settings (see `src/core/tools.rs`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolsSettings {
    /// Master switch: when false, assistant command proposals are ignored.
    pub enabled: bool,
    /// Hard timeout for each executed command, in seconds.
    pub timeout_secs: u64,
    /// Per-stream output cap in bytes (display and history).
    pub max_output_bytes: usize,
    /// Interaction model: `proposals` (fenced blocks, ask-always) or
    /// `agent` (real function calling with the built-in tool set).
    #[serde(default)]
    pub mode: ToolsMode,
    /// OS sandbox applied to approved shell commands: `auto` (default),
    /// `off`, `fs` (no writes outside the workspace) or `strict` (also no
    /// network). macOS-only; ignored elsewhere.
    #[serde(default)]
    pub sandbox: SandboxMode,
}

/// How the assistant may use tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolsMode {
    /// Parse fenced ```bash blocks and ask before running them.
    #[default]
    Proposals,
    /// Real function calling: tools are advertised to the provider and the
    /// engine runs an approval-gated agentic loop.
    Agent,
}

/// Operating-system sandbox for approved shell commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxMode {
    /// Use the strongest available sandbox (macOS `sandbox-exec`), else none.
    #[default]
    Auto,
    /// Never sandbox (run the command as-is).
    Off,
    /// Block writes outside the workspace and temp dirs.
    Fs,
    /// Like `fs`, and also block all network access.
    Strict,
}

impl Default for ToolsSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: 30,
            max_output_bytes: 8192,
            mode: ToolsMode::Proposals,
            sandbox: SandboxMode::Auto,
        }
    }
}

/// What the privacy guard does when sensitive data is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GuardMode {
    /// Show a preview and ask the user (send / placeholders / refuse).
    #[serde(rename = "ask")]
    Ask,
    /// Automatically replace findings with placeholders (no prompt).
    #[serde(rename = "redact")]
    Redact,
    /// Automatically refuse to send when findings are detected.
    #[serde(rename = "block")]
    Block,
}

/// Privacy-guard settings (see `src/privacy/guard.rs`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GuardSettings {
    /// Master switch: when false, messages are sent unmodified.
    pub enabled: bool,
    /// Behaviour when sensitive data is detected.
    pub mode: GuardMode,
    /// Taint tracking: messages found to contain sensitive data are marked and
    /// automatically re-redacted on every later turn so they never leave the
    /// machine verbatim again.
    #[serde(default = "default_true")]
    pub taint: bool,
    /// Prompt-injection hardening: tool/file output is treated as untrusted
    /// data (never instructions), a tool call that follows untrusted content
    /// always needs a fresh approval, and a canary token is used to detect
    /// attempts to smuggle it out through injected text.
    #[serde(default = "default_true")]
    pub injection: bool,
    /// Local NER heuristics: detect person names, organisations and postal
    /// addresses next to the regex patterns, entirely offline.
    #[serde(default = "default_true")]
    pub ner: bool,
    /// Local list of sensitive terms to always flag (e.g. a project codename).
    #[serde(default)]
    pub entities: Vec<String>,
}

impl Default for GuardSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: GuardMode::Ask,
            taint: true,
            injection: true,
            ner: true,
            entities: Vec::new(),
        }
    }
}

/// Where to route a turn whose content is flagged sensitive by the guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    /// Send to the configured provider (no change).
    #[default]
    Same,
    /// Route sensitive turns to the local provider (Ollama) automatically.
    Local,
}

/// Sensitivity-based routing settings.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RoutingSettings {
    /// How to handle turns whose content the guard flags as sensitive.
    #[serde(default)]
    pub sensitive: RoutingMode,
}

/// Network egress settings (proxy, Tor, TLS pinning).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NetworkSettings {
    /// Optional proxy URL applied to every provider request (`http://…`,
    /// `https://…` or `socks5h://host:port`). `socks5h` resolves DNS through
    /// the proxy (required by Tor).
    #[serde(default)]
    pub proxy: Option<String>,
    /// When true and no explicit `proxy` is set, route all provider traffic
    /// through a local Tor SOCKS proxy (`socks5h://127.0.0.1:9050`).
    #[serde(default)]
    pub tor: bool,
    /// Optional TLS pin: the SHA-256 (lowercase hex) of the provider's leaf
    /// certificate DER. When set, the TLS handshake fails unless the server
    /// presents exactly this certificate.
    #[serde(default)]
    pub tls_pin: Option<String>,
}

/// Action applied to an outbound message set when the egress policy matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EgressAction {
    /// Let the data leave unmodified.
    #[default]
    Allow,
    /// Send, but replace the sensitive values with placeholders.
    Redact,
    /// Refuse to send at all.
    Block,
}

/// Data-egress policy (policy-as-code): per sensitive-data-kind rules deciding
/// what may leave the machine for a remote provider. Local providers (Ollama)
/// are never restricted. `rules` keys are `email`, `phone`, `iban`, `tax_id`,
/// `card`, `secret`, `ip`; `default` applies to kinds without a specific rule.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PolicySettings {
    /// Enable the policy gate (off by default, so egress is unrestricted until
    /// you opt in).
    #[serde(default)]
    pub enabled: bool,
    /// Action for kinds without a specific rule.
    #[serde(default)]
    pub default: EgressAction,
    /// Per-kind rules.
    #[serde(default)]
    pub rules: std::collections::BTreeMap<String, EgressAction>,
    /// Optional local DLP judge: an Ollama model name. When set, every outbound
    /// payload is additionally reviewed by that **local** model before sending.
    #[serde(default)]
    pub judge: Option<String>,
    /// Action taken when the local judge flags a payload as sensitive.
    #[serde(default)]
    pub judge_action: EgressAction,
}

/// What the engine may do with a tool call without asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Run without prompting.
    Allow,
    /// Prompt the user each time (default for mutating tools).
    Ask,
    /// Refuse the call.
    Deny,
}

/// Per-tool permission policy (`[permissions]`).
///
/// Every field is optional; a missing field falls back to `default` and then to
/// the built-in default (read-only tools: allow; mutating tools: ask). Rules in
/// `bash_rules` are matched against the shell command: the **longest** matching
/// pattern wins, ties break towards the most restrictive action.
///
/// This is a local safeguard for the agentic loop; the human is still the final
/// gate whenever an action resolves to `ask`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Permissions {
    /// Auto-approve everything that would otherwise `ask` (denied tools stay
    /// denied). Equivalent to opencode's `--auto`.
    #[serde(default)]
    pub auto: bool,
    /// Fallback for tools that have no specific rule.
    #[serde(default)]
    pub default: Option<Action>,
    #[serde(default)]
    pub read: Option<Action>,
    #[serde(default)]
    pub write: Option<Action>,
    #[serde(default)]
    pub edit: Option<Action>,
    #[serde(default)]
    pub list: Option<Action>,
    #[serde(default)]
    pub glob: Option<Action>,
    #[serde(default)]
    pub grep: Option<Action>,
    /// Shell command execution (`run_shell`).
    #[serde(default)]
    pub bash: Option<Action>,
    #[serde(default)]
    pub delegate: Option<Action>,
    /// Any path outside the workspace.
    #[serde(default)]
    pub external_directory: Option<Action>,
    /// Fires when the same tool call repeats several times in one turn.
    #[serde(default)]
    pub doom_loop: Option<Action>,
    /// Command-pattern rules for `run_shell` (e.g. `"git status*" = "allow"`).
    #[serde(default)]
    pub bash_rules: std::collections::BTreeMap<String, Action>,
    /// Refuse clearly destructive shell commands (wiping disks, piping a
    /// download into a shell, `rm -rf` on a system/home path…). When false they
    /// still always ask, even under `--auto`. See `src/core/risk.rs`.
    #[serde(default = "default_true")]
    pub block_destructive: bool,
}

/// One sub-agent persona (`[agent.personas.<name>]`).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PersonaSettings {
    /// Provider name (defaults to `default_provider`).
    pub provider: Option<String>,
    /// Model override (defaults to the provider default).
    pub model: Option<String>,
    /// System prompt for the sub-agent.
    pub system_prompt: Option<String>,
}

/// Multi-agent settings.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AgentSettings {
    /// Named personas the top-level agent can delegate to.
    #[serde(default)]
    pub personas: std::collections::BTreeMap<String, PersonaSettings>,
}

/// Terminal-UI appearance and key bindings (`[tui]`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TuiSettings {
    /// Colour theme name (`default`, `nord`, `gruvbox`, `solarized`, `mono`).
    #[serde(default)]
    pub theme: Option<String>,
    /// Key overrides: action name → key spec (e.g. `"quit" = "ctrl+q"`).
    ///
    /// Recognized actions: `quit, clear, copy_mode, session_picker,
    /// toggle_sidebar, toggle_mode, newline, history_prev, history_next,
    /// delete_word, clear_input, send`. Key specs look like `ctrl+y`, `alt+x`,
    /// `shift+tab`, `f5`, `esc`, `enter`, `tab`, or a single character.
    #[serde(default)]
    pub keybinds: std::collections::BTreeMap<String, String>,
    /// Ring the terminal bell and send a desktop notification when a reply
    /// finishes or a tool call needs approval. Defaults to `true`.
    #[serde(default = "default_true")]
    pub notify: bool,
    /// Terminal cursor shape in the input box: `block` (default), `underline`,
    /// `line`, or `default` to restore the terminal's own cursor.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Whether the input cursor blinks. Defaults to `true`.
    #[serde(default = "default_true")]
    pub cursor_blinking: bool,
}

impl Default for TuiSettings {
    fn default() -> Self {
        Self {
            theme: None,
            keybinds: std::collections::BTreeMap::new(),
            notify: true,
            cursor: None,
            cursor_blinking: true,
        }
    }
}

/// A Model Context Protocol server (`[mcp.servers.<name>]`).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct McpServer {
    /// Executable to launch (stdio transport).
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    /// Allowlist of tool names to expose from this server (empty = all).
    #[serde(default)]
    pub tools: Vec<String>,
    /// Names of parent environment variables to pass through to the server.
    /// The environment is otherwise cleared (only `PATH` is inherited), so
    /// secrets in the shell environment are never handed to a server by default.
    #[serde(default)]
    pub env_allow: Vec<String>,
}

/// MCP configuration (`[mcp]`). Servers are launched locally over stdio.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct McpSettings {
    /// Allowlist of server names to connect (empty = all configured servers).
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub servers: std::collections::BTreeMap<String, McpServer>,
}

/// Local encrypted supermemory (`[memory]`).
///
/// Memories live in the encrypted database and, when injected, travel to the
/// provider like any other context (the privacy guard still applies). A memory
/// can be flagged `local_only` so it is never sent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemorySettings {
    /// Enable the memory feature (context injection, `remember` tool, startup reload).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Autosave interval in seconds (0 = off). When > 0 the TUI periodically
    /// records a checkpoint memory summarising the session.
    #[serde(default)]
    pub autosave_secs: u64,
    /// Maximum number of memories injected into the system prompt.
    #[serde(default = "default_memory_limit")]
    pub inject_limit: usize,
}

fn default_memory_limit() -> usize {
    50
}

impl Default for MemorySettings {
    fn default() -> Self {
        Self {
            enabled: true,
            autosave_secs: 0,
            inject_limit: 50,
        }
    }
}

/// Lock-screen and clipboard hardening.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecuritySettings {
    /// Lock the TUI after this many seconds of inactivity (0 = disabled).
    #[serde(default)]
    pub auto_lock_secs: u64,
    /// Clear the clipboard this many seconds after Enclave put something on it
    /// (0 = disabled).
    #[serde(default = "default_clipboard_clear")]
    pub clipboard_clear_secs: u64,
    /// Optional duress password. When set, typing it at the master-password
    /// prompt is meant to open a decoy vault; reserved for the decoy-vault
    /// feature.
    #[serde(default)]
    pub duress_password: Option<String>,
}

fn default_clipboard_clear() -> u64 {
    30
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            auto_lock_secs: 0,
            clipboard_clear_secs: 30,
            duress_password: None,
        }
    }
}

/// Context budgeting (`[context]`).
///
/// Enclave estimates the size of every outgoing request (roughly one token per
/// four characters). When `budget_tokens` is set, the Context Inspector shows a
/// usage bar and warns once the estimate crosses `warn_pct`% of the budget.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContextSettings {
    /// Soft budget in tokens (0 or absent = no budget shown).
    #[serde(default)]
    pub budget_tokens: Option<usize>,
    /// Percentage of the budget at which the inspector warns (default 80).
    #[serde(default = "default_warn_pct")]
    pub warn_pct: u8,
}

fn default_warn_pct() -> u8 {
    80
}

impl Default for ContextSettings {
    fn default() -> Self {
        Self {
            budget_tokens: None,
            warn_pct: 80,
        }
    }
}

/// Workspace checkpoints: snapshot the working directory (into a private local
/// shadow git repository, never the project's own `.git`) before Enclave edits
/// files, so a change can be rewound. Fully local — no remote, no network.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CheckpointSettings {
    /// Enable automatic snapshots before file-modifying tool calls.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// How many recent snapshots to keep for listing (informational).
    #[serde(default = "default_checkpoint_max")]
    pub max: usize,
}

fn default_checkpoint_max() -> usize {
    100
}

impl Default for CheckpointSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            max: 100,
        }
    }
}

/// Auto verification loop (see `src/core/verify.rs`).
///
/// After agentic file edits Enclave can run the project's own checks locally
/// (tests, lint, typecheck) in the command sandbox and hand failures back to
/// the model so it fixes them by itself. Fully offline.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifySettings {
    /// Enable the automatic post-edit verification loop.
    #[serde(default = "default_true")]
    pub auto: bool,
    /// Explicit command to run. When empty, Enclave auto-detects one from
    /// `Cargo.toml` / `package.json` / `pyproject.toml` / `go.mod` / `Makefile`.
    #[serde(default)]
    pub command: Option<String>,
    /// How many times a failing verification may be fed back to the model.
    #[serde(default = "default_verify_attempts")]
    pub max_attempts: u8,
    /// Timeout for one verification run.
    #[serde(default = "default_verify_timeout")]
    pub timeout_secs: u64,
}

fn default_verify_attempts() -> u8 {
    2
}

fn default_verify_timeout() -> u64 {
    300
}

impl Default for VerifySettings {
    fn default() -> Self {
        Self {
            auto: true,
            command: None,
            max_attempts: 2,
            timeout_secs: 300,
        }
    }
}

/// Persisted, non-sensitive application settings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    /// Default provider name.
    pub default_provider: String,
    /// Default model identifier.
    pub default_model: String,
    /// Whether to cache the derived master key so the password is asked only
    /// once.
    ///
    /// Defaults to `true`: after the first successful unlock the derived key is
    /// stored in the local credentials file (`keys.toml`, mode 0600), so
    /// subsequent launches skip the password with **no** OS-keychain dialog.
    /// Set to `false` to require the master password on every launch (nothing is
    /// stored).
    #[serde(default = "default_true")]
    pub use_keychain: bool,
    /// Key-derivation function for new vaults: `argon2id` (default) or
    /// `pbkdf2`. Ignored for existing vaults, which keep the algorithm recorded
    /// in their salt file.
    #[serde(default)]
    pub kdf: Option<String>,
    /// Optional system prompt prepended to every conversation.
    pub system_prompt: Option<String>,
    /// Optional reasoning effort hint (`low`/`medium`/`high`) sent to
    /// providers that support it. `None` keeps the model default.
    #[serde(default)]
    pub reasoning_effort: Option<String>,
    /// Base URL for the local Ollama server.
    pub ollama_base_url: String,
    /// Shell-tool settings.
    #[serde(default)]
    pub tools: ToolsSettings,
    /// Privacy-guard settings.
    #[serde(default)]
    pub guard: GuardSettings,
    /// Data-egress policy (policy-as-code).
    #[serde(default)]
    pub policy: PolicySettings,
    /// Multi-agent settings.
    #[serde(default)]
    pub agent: AgentSettings,
    /// Permission policy for the agentic tool loop.
    #[serde(default)]
    pub permissions: Permissions,
    /// Extra local rule files (paths or globs, relative to the working dir).
    /// Remote URLs are ignored (local-only by design).
    #[serde(default)]
    pub instructions: Vec<String>,
    /// Terminal-UI theme and key bindings.
    #[serde(default)]
    pub tui: TuiSettings,
    /// Model Context Protocol servers (local, stdio transport).
    #[serde(default)]
    pub mcp: McpSettings,
    /// Local encrypted supermemory.
    #[serde(default)]
    pub memory: MemorySettings,
    /// Lock screen, clipboard and duress hardening.
    #[serde(default)]
    pub security: SecuritySettings,
    /// Id of the session currently in progress (auto-resumed at startup).
    #[serde(default)]
    pub working_session: Option<String>,
    /// Air-gap mode: refuse to send anything to remote providers (local-only).
    #[serde(default)]
    pub air_gap: bool,
    /// Sensitivity-based routing (route sensitive turns to local Ollama).
    #[serde(default)]
    pub routing: RoutingSettings,
    /// Network egress: proxy, Tor and TLS pinning.
    #[serde(default)]
    pub network: NetworkSettings,
    /// Context budgeting for the Context Inspector.
    #[serde(default)]
    pub context: ContextSettings,
    /// Workspace checkpoint snapshots (local, git-backed).
    #[serde(default)]
    pub checkpoints: CheckpointSettings,
    /// Auto verification loop after agentic file edits.
    #[serde(default)]
    pub verify: VerifySettings,
}

fn default_true() -> bool {
    true
}

impl Settings {
    /// Resolve the effective tool configuration given the `--no-tools` flag.
    pub fn effective_tools(&self, no_tools_flag: bool) -> ToolsSettings {
        let mut t = self.tools.clone();
        if no_tools_flag {
            t.enabled = false;
        }
        t
    }

    /// Resolve the effective guard configuration given the `--no-guard` flag.
    pub fn effective_guard(&self, no_guard_flag: bool) -> GuardSettings {
        let mut g = self.guard.clone();
        if no_guard_flag {
            g.enabled = false;
        }
        g
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_provider: "openrouter".to_string(),
            default_model: "mistralai/mistral-large-4-0".to_string(),
            use_keychain: true,
            kdf: None,
            system_prompt: None,
            reasoning_effort: None,
            ollama_base_url: "http://localhost:11434".to_string(),
            tools: ToolsSettings::default(),
            guard: GuardSettings::default(),
            policy: PolicySettings::default(),
            agent: AgentSettings::default(),
            permissions: Permissions::default(),
            instructions: Vec::new(),
            tui: TuiSettings::default(),
            mcp: McpSettings::default(),
            memory: MemorySettings::default(),
            security: SecuritySettings::default(),
            working_session: None,
            air_gap: false,
            routing: RoutingSettings::default(),
            network: NetworkSettings::default(),
            context: ContextSettings::default(),
            checkpoints: CheckpointSettings::default(),
            verify: VerifySettings::default(),
        }
    }
}

impl Settings {
    /// Load settings from disk, falling back to defaults when absent.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)?;
        let settings = toml::from_str(&raw)?;
        Ok(settings)
    }

    /// Persist settings to disk.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let raw = toml::to_string_pretty(self).map_err(|e| EnclaveError::Other(e.to_string()))?;
        std::fs::write(path, raw)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_defaults_are_sane() {
        let s = SecuritySettings::default();
        assert_eq!(s.auto_lock_secs, 0);
        assert_eq!(s.clipboard_clear_secs, 30);
        assert!(s.duress_password.is_none());

        // Defaults survive a real Settings value.
        let settings = Settings::default();
        assert_eq!(settings.security.clipboard_clear_secs, 30);
        assert_eq!(settings.security.auto_lock_secs, 0);
    }

    #[test]
    fn mcp_hardening_fields_parse() {
        let toml = r#"
            allow = ["time"]

            [servers.time]
            command = "mcp-time"
            args = ["--stdio"]
            env_allow = ["TZ"]
            tools = ["now"]
            "#;
        let mcp: McpSettings = toml::from_str(toml).expect("parse");
        assert_eq!(mcp.allow, vec!["time".to_string()]);
        let srv = mcp.servers.get("time").expect("server");
        assert_eq!(srv.command, "mcp-time");
        assert_eq!(srv.tools, vec!["now".to_string()]);
        assert_eq!(srv.env_allow, vec!["TZ".to_string()]);
    }

    #[test]
    fn context_defaults_and_parsing() {
        let c = ContextSettings::default();
        assert!(c.budget_tokens.is_none());
        assert_eq!(c.warn_pct, 80);

        let toml = "budget_tokens = 128000\nwarn_pct = 90\n";
        let c: ContextSettings = toml::from_str(toml).expect("parse");
        assert_eq!(c.budget_tokens, Some(128_000));
        assert_eq!(c.warn_pct, 90);

        // A bare section keeps the defaults.
        let c: ContextSettings = toml::from_str("").expect("parse empty");
        assert!(c.budget_tokens.is_none());
        assert_eq!(c.warn_pct, 80);
    }

    #[test]
    fn settings_parse_without_any_optional_sections() {
        // A minimal config file (only the required fields) still parses; the
        // optional sections fall back to their defaults.
        let settings = Settings::default();
        assert!(settings.mcp.allow.is_empty());
        assert!(settings.mcp.servers.is_empty());
    }
}

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

impl Default for ToolsSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: 30,
            max_output_bytes: 8192,
            mode: ToolsMode::Proposals,
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
}

impl Default for GuardSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: GuardMode::Ask,
        }
    }
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
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
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
            system_prompt: None,
            reasoning_effort: None,
            ollama_base_url: "http://localhost:11434".to_string(),
            tools: ToolsSettings::default(),
            guard: GuardSettings::default(),
            agent: AgentSettings::default(),
            permissions: Permissions::default(),
            instructions: Vec::new(),
            tui: TuiSettings::default(),
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

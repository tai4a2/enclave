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
}

impl Default for ToolsSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: 30,
            max_output_bytes: 8192,
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

/// Persisted, non-sensitive application settings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    /// Default provider name.
    pub default_provider: String,
    /// Default model identifier.
    pub default_model: String,
    /// Whether to cache the master key in the OS keychain.
    pub use_keychain: bool,
    /// Optional system prompt prepended to every conversation.
    pub system_prompt: Option<String>,
    /// Base URL for the local Ollama server.
    pub ollama_base_url: String,
    /// Shell-tool settings.
    #[serde(default)]
    pub tools: ToolsSettings,
    /// Privacy-guard settings.
    #[serde(default)]
    pub guard: GuardSettings,
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
            ollama_base_url: "http://localhost:11434".to_string(),
            tools: ToolsSettings::default(),
            guard: GuardSettings::default(),
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

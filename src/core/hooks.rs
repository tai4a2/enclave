//! Local tool hooks: user-configured shell commands run around every tool call.
//!
//! A `pre_tool` hook runs *before* the tool and can block it by exiting with a
//! non-zero status; a `post_tool` hook runs after it. Both receive the tool
//! name and its raw JSON arguments through environment variables
//! (`ENCLAVE_HOOK_EVENT`, `ENCLAVE_TOOL`, `ENCLAVE_TOOL_ARGS`). Hooks are
//! entirely local — Enclave only shells out to the command you configure, in
//! the same sandbox as `run_shell`.

use std::path::Path;

use crate::config::HooksSettings;
use crate::core::tools::{self, Sandbox};
use crate::error::Result;

/// Outcome of a hook run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookOutcome {
    /// True when the hook failed (non-zero exit or timeout) — blocks the tool.
    pub blocked: bool,
    /// Combined command output (stdout + stderr, already rendered).
    pub output: String,
}

/// Single-quote a string for safe interpolation into `sh -c`.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The hooks usable by the tool layer (only present when configured).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hooks {
    pub pre_tool: Option<String>,
    pub post_tool: Option<String>,
    pub timeout_secs: u64,
}

impl Hooks {
    /// Build from settings; `None` when no hook is configured.
    pub fn from_settings(settings: &HooksSettings) -> Option<Self> {
        let pre = settings.pre_tool.clone().filter(|c| !c.trim().is_empty());
        let post = settings.post_tool.clone().filter(|c| !c.trim().is_empty());
        if pre.is_none() && post.is_none() {
            return None;
        }
        Some(Self {
            pre_tool: pre,
            post_tool: post,
            timeout_secs: settings.timeout_secs.max(1),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.pre_tool.is_none() && self.post_tool.is_none()
    }
}

/// Run a hook command with the tool context in the environment.
pub async fn run_hook(
    command: &str,
    event: &str,
    tool: &str,
    arguments: &str,
    workspace: &Path,
    timeout_secs: u64,
    sandbox: Option<&Sandbox>,
) -> Result<HookOutcome> {
    let wrapped = format!(
        "ENCLAVE_HOOK_EVENT={} ENCLAVE_TOOL={} ENCLAVE_TOOL_ARGS={} ENCLAVE_WORKSPACE={} sh -c {}",
        sh_quote(event),
        sh_quote(tool),
        sh_quote(arguments),
        sh_quote(&workspace.to_string_lossy()),
        sh_quote(command),
    );
    let out = tools::run_sandboxed(
        &wrapped,
        std::time::Duration::from_secs(timeout_secs),
        crate::core::tools::DEFAULT_MAX_OUTPUT_BYTES,
        sandbox,
    )
    .await?;
    Ok(HookOutcome {
        blocked: out.timed_out || out.code.unwrap_or(0) != 0,
        output: out.render(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HooksSettings;

    #[test]
    fn from_settings_is_none_without_commands() {
        assert!(Hooks::from_settings(&HooksSettings::default()).is_none());
        let s = HooksSettings {
            pre_tool: Some("  ".to_string()),
            post_tool: Some("echo hi".to_string()),
            ..Default::default()
        };
        let hooks = Hooks::from_settings(&s).unwrap();
        assert!(hooks.pre_tool.is_none());
        assert_eq!(hooks.post_tool.as_deref(), Some("echo hi"));
    }

    #[test]
    fn sh_quote_escapes_single_quotes() {
        assert_eq!(sh_quote("a'b"), "'a'\\''b'");
    }

    #[tokio::test]
    async fn pre_hook_can_block_and_receives_env() {
        let tmp = tempfile::tempdir().unwrap();
        let ok = run_hook(
            "test \"$ENCLAVE_TOOL\" = run_shell",
            "pre",
            "run_shell",
            "{}",
            tmp.path(),
            10,
            None,
        )
        .await
        .unwrap();
        assert!(!ok.blocked, "hook should pass: {}", ok.output);

        let blocked = run_hook("exit 3", "pre", "write_file", "{}", tmp.path(), 10, None)
            .await
            .unwrap();
        assert!(blocked.blocked);
    }
}

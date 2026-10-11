//! Built-in agent tools with a workspace sandbox.
//!
//! Security properties:
//! - every call goes through the engine's `ToolGate` (ask-always by default);
//! - file paths are confined to the workspace directory (`..` rejected,
//!   absolute paths only if inside the workspace);
//! - `run_shell` reuses the hardened proposal runner (timeout, kill, cap);
//! - tool output is capped before it is persisted or sent to the provider.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use crate::core::engine::ToolGate;
use crate::core::message::ToolCall;
use crate::core::tools as shell;
use crate::error::{EnclaveError, Result};
use crate::providers::ToolDef;

/// Closure that runs a sub-agent (multi-agent `delegate` tool).
pub type DelegateFn = Box<
    dyn for<'a> Fn(
            &'a str,
            &'a str,
            &'a mut dyn ToolGate,
        ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>>
        + Send
        + Sync,
>;

/// Runtime context for tool execution.
pub struct ToolContext {
    /// Root directory: file tools cannot escape it.
    pub workspace: PathBuf,
    pub shell_timeout_secs: u64,
    pub max_output_bytes: usize,
    /// Present only on the top-level agent (depth limit for delegation).
    pub delegate: Option<DelegateFn>,
}

/// The built-in tool set. `with_delegate` adds the multi-agent tool.
pub fn defs(with_delegate: bool) -> Vec<ToolDef> {
    let mut tools = vec![
        ToolDef::new(
            "read_file",
            "Read a text file inside the workspace.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "relative or workspace-absolute path"}
                },
                "required": ["path"]
            }),
        ),
        ToolDef::new(
            "write_file",
            "Create or overwrite a text file inside the workspace.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"}
                },
                "required": ["path", "content"]
            }),
        ),
        ToolDef::new(
            "list_dir",
            "List the entries of a directory inside the workspace.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "defaults to the workspace root"}
                },
                "required": []
            }),
        ),
        ToolDef::new(
            "run_shell",
            "Run a shell command (sh -c) inside the workspace. Subject to approval.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "command": {"type": "string"}
                },
                "required": ["command"]
            }),
        ),
    ];
    if with_delegate {
        tools.push(ToolDef::new(
            "delegate",
            "Delegate a task to a named sub-agent persona and get its answer.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "agent": {"type": "string", "description": "persona name"},
                    "task": {"type": "string"}
                },
                "required": ["agent", "task"]
            }),
        ));
    }
    tools
}

/// Resolve `raw` inside `workspace`, refusing escapes.
pub fn resolve_in_workspace(workspace: &Path, raw: &str) -> Result<PathBuf> {
    let p = Path::new(raw);
    if p.components().any(|c| c == std::path::Component::ParentDir) {
        return Err(EnclaveError::other("path traversal rejected ('..' not allowed)"));
    }
    // Canonicalize the workspace too: on macOS /var is a symlink to /private/var.
    let ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_path_buf());
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        ws.join(p)
    };
    // Best effort canonicalization (fails for not-yet-existing files).
    let canon = joined
        .canonicalize()
        .unwrap_or_else(|_| joined.clone());
    if !canon.starts_with(&ws) {
        return Err(EnclaveError::other(format!(
            "path '{}' is outside the workspace",
            raw
        )));
    }
    Ok(canon)
}

fn cap(data: &[u8], max: usize) -> (String, bool) {
    if data.len() <= max {
        (String::from_utf8_lossy(data).into_owned(), false)
    } else {
        let mut end = max;
        while end > 0 && std::str::from_utf8(&data[..end]).is_err() {
            end -= 1;
        }
        (
            String::from_utf8_lossy(&data[..end]).into_owned(),
            true,
        )
    }
}

/// Execute one tool call. Unknown tools are reported, not guessed.
pub async fn execute(
    call: &ToolCall,
    ctx: &ToolContext,
    gate: &mut dyn ToolGate,
) -> Result<String> {
    let args: serde_json::Value =
        serde_json::from_str(&call.arguments).unwrap_or_else(|_| serde_json::json!({}));
    let arg_str = |key: &str| args[key].as_str().unwrap_or_default().to_string();

    match call.name.as_str() {
        "read_file" => {
            let path = resolve_in_workspace(&ctx.workspace, &arg_str("path"))?;
            let data = std::fs::read(&path)?;
            let (text, truncated) = cap(&data, ctx.max_output_bytes);
            Ok(if truncated {
                format!("{text}\n[truncated at {} bytes]", ctx.max_output_bytes)
            } else {
                text
            })
        }
        "write_file" => {
            let path = resolve_in_workspace(&ctx.workspace, &arg_str("path"))?;
            let content = arg_str("content");
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, &content)?;
            Ok(format!("wrote {} bytes to {}", content.len(), path.display()))
        }
        "list_dir" => {
            let raw = arg_str("path");
            let path = if raw.is_empty() {
                ctx.workspace.clone()
            } else {
                resolve_in_workspace(&ctx.workspace, &raw)?
            };
            let mut entries: Vec<String> = std::fs::read_dir(&path)?
                .filter_map(|e| e.ok())
                .map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        format!("{name}/")
                    } else {
                        name
                    }
                })
                .collect();
            entries.sort();
            Ok(if entries.is_empty() {
                "(empty directory)".to_string()
            } else {
                entries.join("\n")
            })
        }
        "run_shell" => {
            let command = arg_str("command");
            let timeout = std::time::Duration::from_secs(ctx.shell_timeout_secs.max(1));
            let out = shell::run(&command, timeout, ctx.max_output_bytes).await?;
            Ok(out.render())
        }
        "delegate" => match &ctx.delegate {
            Some(delegate) => delegate(&arg_str("agent"), &arg_str("task"), gate).await,
            None => Err(EnclaveError::other(
                "delegation not available (no personas configured)",
            )),
        },
        other => Err(EnclaveError::other(format!("unknown tool '{other}'"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_confines_relative_paths() {
        let ws = Path::new("/tmp/ws");
        assert_eq!(
            resolve_in_workspace(ws, "a/b.txt").unwrap(),
            PathBuf::from("/tmp/ws/a/b.txt")
        );
        assert!(resolve_in_workspace(ws, "../escape").is_err());
        assert!(resolve_in_workspace(ws, "a/../../escape").is_err());
    }

    #[test]
    fn workspace_confines_absolute_paths() {
        let ws = Path::new("/tmp/ws");
        assert_eq!(
            resolve_in_workspace(ws, "/tmp/ws/inner/f").unwrap(),
            PathBuf::from("/tmp/ws/inner/f")
        );
        assert!(resolve_in_workspace(ws, "/etc/passwd").is_err());
    }

    #[test]
    fn defs_shape_and_delegate_flag() {
        let base = defs(false);
        assert_eq!(base.len(), 4);
        assert!(base.iter().all(|d| !d.name.is_empty()));
        let with = defs(true);
        assert_eq!(with.len(), 5);
        assert_eq!(with[4].name, "delegate");
    }
}
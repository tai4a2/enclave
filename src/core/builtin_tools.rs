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

use crate::core::diff;
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

/// Summary of a file modification, for the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChange {
    pub path: String,
    pub added: usize,
    pub removed: usize,
}

/// Structured tool result: rendered text plus an optional file change.
#[derive(Debug, Clone)]
pub struct ToolOutcome {
    pub text: String,
    pub change: Option<FileChange>,
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
            "edit_file",
            "Replace an exact string in a text file inside the workspace (fails if not found or ambiguous).",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "old_string": {"type": "string", "description": "exact text to replace"},
                    "new_string": {"type": "string", "description": "replacement text"}
                },
                "required": ["path", "old_string", "new_string"]
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

/// Execute one tool call, returning rendered text and any file change.
/// Unknown tools are reported, not guessed.
pub async fn execute_detailed(
    call: &ToolCall,
    ctx: &ToolContext,
    gate: &mut dyn ToolGate,
) -> Result<ToolOutcome> {
    let args: serde_json::Value =
        serde_json::from_str(&call.arguments).unwrap_or_else(|_| serde_json::json!({}));
    let arg_str = |key: &str| args[key].as_str().unwrap_or_default().to_string();

    match call.name.as_str() {
        "read_file" => {
            let path = resolve_in_workspace(&ctx.workspace, &arg_str("path"))?;
            let data = std::fs::read(&path)?;
            let (text, truncated) = cap(&data, ctx.max_output_bytes);
            let text = if truncated {
                format!("{text}\n[truncated at {} bytes]", ctx.max_output_bytes)
            } else {
                text
            };
            Ok(ToolOutcome { text, change: None })
        }
        "write_file" => {
            let path = resolve_in_workspace(&ctx.workspace, &arg_str("path"))?;
            let content = arg_str("content");
            let old = std::fs::read_to_string(&path).unwrap_or_default();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, &content)?;
            let d = diff::lines(&old, &content);
            let (added, removed) = diff::stats(&d);
            let body = diff::render(&d, 400);
            let text = if old.is_empty() {
                format!("created {} (+{} lines)\n{}", path.display(), added, body)
            } else {
                format!(
                    "wrote {} bytes to {} (+{} \u{2212}{})\n{}",
                    content.len(),
                    path.display(),
                    added,
                    removed,
                    body
                )
            };
            Ok(ToolOutcome {
                text,
                change: Some(FileChange {
                    path: path.display().to_string(),
                    added,
                    removed,
                }),
            })
        }
        "edit_file" => {
            let path = resolve_in_workspace(&ctx.workspace, &arg_str("path"))?;
            let old_string = arg_str("old_string");
            let new_string = arg_str("new_string");
            if old_string.is_empty() {
                return Err(EnclaveError::other("old_string must not be empty"));
            }
            let old = std::fs::read_to_string(&path)
                .map_err(|e| EnclaveError::other(format!("cannot read {}: {e}", path.display())))?;
            let count = old.matches(&old_string).count();
            if count == 0 {
                return Err(EnclaveError::other(format!(
                    "old_string not found in {}",
                    path.display()
                )));
            }
            if count > 1 {
                return Err(EnclaveError::other(format!(
                    "old_string is ambiguous ({count} matches) in {}",
                    path.display()
                )));
            }
            let new = old.replacen(&old_string, &new_string, 1);
            std::fs::write(&path, &new)?;
            let d = diff::lines(&old, &new);
            let (added, removed) = diff::stats(&d);
            let text = format!(
                "edited {} (+{} \u{2212}{})\n{}",
                path.display(),
                added,
                removed,
                diff::render(&d, 400)
            );
            Ok(ToolOutcome {
                text,
                change: Some(FileChange {
                    path: path.display().to_string(),
                    added,
                    removed,
                }),
            })
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
            let text = if entries.is_empty() {
                "(empty directory)".to_string()
            } else {
                entries.join("\n")
            };
            Ok(ToolOutcome { text, change: None })
        }
        "run_shell" => {
            let command = arg_str("command");
            let timeout = std::time::Duration::from_secs(ctx.shell_timeout_secs.max(1));
            let out = shell::run(&command, timeout, ctx.max_output_bytes).await?;
            Ok(ToolOutcome {
                text: out.render(),
                change: None,
            })
        }
        "delegate" => match &ctx.delegate {
            Some(delegate) => {
                let text = delegate(&arg_str("agent"), &arg_str("task"), gate).await?;
                Ok(ToolOutcome { text, change: None })
            }
            None => Err(EnclaveError::other(
                "delegation not available (no personas configured)",
            )),
        },
        other => Err(EnclaveError::other(format!("unknown tool '{other}'"))),
    }
}

/// Execute one tool call, returning only the rendered text.
pub async fn execute(
    call: &ToolCall,
    ctx: &ToolContext,
    gate: &mut dyn ToolGate,
) -> Result<String> {
    Ok(execute_detailed(call, ctx, gate).await?.text)
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
        assert_eq!(base.len(), 5);
        assert!(base.iter().all(|d| !d.name.is_empty()));
        assert!(base.iter().any(|d| d.name == "edit_file"));
        let with = defs(true);
        assert_eq!(with.len(), 6);
        assert_eq!(with[5].name, "delegate");
    }

    fn ctx_at(ws: &Path) -> ToolContext {
        ToolContext {
            workspace: ws.to_path_buf(),
            shell_timeout_secs: 5,
            max_output_bytes: 8192,
            delegate: None,
        }
    }

    struct AllowAll;
    #[async_trait::async_trait]
    impl ToolGate for AllowAll {
        async fn decide(&mut self, _call: &ToolCall) -> crate::core::engine::ToolDecision {
            crate::core::engine::ToolDecision::Approve
        }
        async fn observe(&mut self, _call: &ToolCall, _output: &str) {}
    }

    #[tokio::test]
    async fn edit_file_replaces_once_and_reports_change() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, "hello world").unwrap();
        let call = ToolCall {
            id: "1".into(),
            name: "edit_file".into(),
            arguments: serde_json::json!({
                "path": "a.txt",
                "old_string": "world",
                "new_string": "enclave"
            })
            .to_string(),
        };
        let out = execute_detailed(&call, &ctx_at(dir.path()), &mut AllowAll)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "hello enclave");
        let change = out.change.expect("expected a file change");
        assert!(change.added >= 1 && change.removed >= 1);
        assert!(out.text.contains("edited"));
    }

    #[tokio::test]
    async fn edit_file_rejects_missing_and_ambiguous_old_string() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "x x").unwrap();
        let missing = ToolCall {
            id: "1".into(),
            name: "edit_file".into(),
            arguments: serde_json::json!({"path":"a.txt","old_string":"zzz","new_string":"y"})
                .to_string(),
        };
        assert!(execute_detailed(&missing, &ctx_at(dir.path()), &mut AllowAll)
            .await
            .is_err());
        let ambiguous = ToolCall {
            id: "2".into(),
            name: "edit_file".into(),
            arguments: serde_json::json!({"path":"a.txt","old_string":"x","new_string":"y"})
                .to_string(),
        };
        assert!(execute_detailed(&ambiguous, &ctx_at(dir.path()), &mut AllowAll)
            .await
            .is_err());
    }
}
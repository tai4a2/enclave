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
use crate::core::permissions::wildcard_match;
use crate::core::tools as shell;
use crate::error::{EnclaveError, Result};
use crate::providers::ToolDef;
use regex::Regex;

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

/// Closure that asks the user a question (interactive `question` tool).
pub type AskFn = Box<
    dyn for<'a> Fn(
            &'a str,
            &'a [String],
        ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>>
        + Send
        + Sync,
>;

/// One entry of the model's task list (`todo` tool).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TodoItem {
    pub text: String,
    /// One of `pending`, `in_progress`, `done`.
    pub status: String,
}

/// Runtime context for tool execution.
pub struct ToolContext {
    /// Root directory: file tools cannot escape it.
    pub workspace: PathBuf,
    pub shell_timeout_secs: u64,
    pub max_output_bytes: usize,
    /// Present only on the top-level agent (depth limit for delegation).
    pub delegate: Option<DelegateFn>,
    /// Present when the UI can prompt the user (`question` tool).
    pub ask: Option<AskFn>,
    /// Shared task list the model can update (`todo` tool).
    pub todos: Option<std::sync::Arc<std::sync::Mutex<Vec<TodoItem>>>>,
    /// Connected MCP servers, if any (`mcp__server__tool` calls).
    pub mcp: Option<std::sync::Arc<crate::core::mcp::McpRegistry>>,
    /// OS sandbox applied to `run_shell` commands (macOS only).
    pub sandbox: Option<crate::core::tools::Sandbox>,
}

impl Default for ToolContext {
    fn default() -> Self {
        ToolContext {
            workspace: std::env::current_dir().unwrap_or_default(),
            shell_timeout_secs: 30,
            max_output_bytes: 8192,
            delegate: None,
            ask: None,
            todos: None,
            mcp: None,
            sandbox: None,
        }
    }
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
            "Read a text file inside the workspace. Use offset/limit to read a line range.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "relative or workspace-absolute path"},
                    "offset": {"type": "integer", "description": "1-based first line to read (optional)"},
                    "limit": {"type": "integer", "description": "number of lines to read (optional)"}
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
            "apply_patch",
            "Apply a unified diff (one or more @@ hunks) to a file inside the workspace. Handles several edits in one call.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "patch": {"type": "string", "description": "unified diff hunks, e.g. @@ -1,3 +1,4 @@ ..."}
                },
                "required": ["path", "patch"]
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
            "glob",
            "Find files by glob pattern (e.g. **/*.rs, src/*.ts). Read-only.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "path": {"type": "string", "description": "directory to search (default: workspace root)"}
                },
                "required": ["pattern"]
            }),
        ),
        ToolDef::new(
            "grep",
            "Search file contents with a regular expression. Read-only.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "regex"},
                    "glob": {"type": "string", "description": "file filter glob (optional)"},
                    "path": {"type": "string", "description": "directory to search (default: workspace root)"}
                },
                "required": ["pattern"]
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
        ToolDef::new(
            "todo",
            "Record or update your task list for the current request. Call it whenever the plan changes so progress stays visible.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "description": "the full, ordered task list",
                        "items": {
                            "type": "object",
                            "properties": {
                                "text": {"type": "string"},
                                "status": {"type": "string", "enum": ["pending", "in_progress", "done"]}
                            },
                            "required": ["text", "status"]
                        }
                    }
                },
                "required": ["items"]
            }),
        ),
        ToolDef::new(
            "question",
            "Ask the user a question when you need a decision or missing information. Optionally provide a list of choices.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "question": {"type": "string"},
                    "options": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "optional suggested answers"
                    }
                },
                "required": ["question"]
            }),
        ),
        ToolDef::new(
            "remember",
            "Save a durable fact, preference or decision to the user's encrypted long-term memory so it is recalled in future sessions.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "the fact to remember"},
                    "tags": {"type": "string", "description": "optional comma-separated tags"},
                    "local_only": {
                        "type": "boolean",
                        "description": "if true, never send this memory to a remote provider"
                    }
                },
                "required": ["text"]
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

/// Directories skipped by `glob`/`grep` (build/VCS noise).
fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | "target" | "node_modules" | ".venv" | "venv" | "__pycache__"
    )
}

/// Recursively collect files under `root` (bounded, symlinks not followed).
fn walk_files(root: &Path, out: &mut Vec<PathBuf>) {
    const MAX_ENTRIES: usize = 20_000;
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > MAX_ENTRIES {
                return;
            }
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            let path = entry.path();
            if file_type.is_dir() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !should_skip_dir(&name) {
                    stack.push(path);
                }
            } else if file_type.is_file() {
                out.push(path);
            }
        }
    }
}

fn relative_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Public helper: all files under `root` (bounded, skipping build/VCS dirs).
pub fn list_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_files(root, &mut out);
    out
}

/// Apply a unified diff (one or more `@@` hunks) to `original`.
///
/// Context (`' '`) and removal (`'-'`) lines must match exactly; lines starting
/// with `---`/`+++`/`diff `/`index ` headers are ignored. Unrecognised lines are
/// treated as context.
pub fn apply_unified(original: &str, patch: &str) -> Result<String> {
    #[derive(Clone, Copy)]
    enum Op {
        Context,
        Remove,
        Add,
    }
    struct Hunk {
        old_start: usize,
        lines: Vec<(Op, String)>,
    }

    let orig_lines: Vec<&str> = original.split('\n').collect();
    let mut hunks: Vec<Hunk> = Vec::new();
    let mut current: Option<Hunk> = None;

    for raw in patch.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(rest) = line.strip_prefix("@@") {
            if let Some(h) = current.take() {
                hunks.push(h);
            }
            let spec = rest.trim_end_matches('@').trim();
            let old_part = spec
                .split_whitespace()
                .next()
                .and_then(|s| s.strip_prefix('-'))
                .unwrap_or("0");
            let old_start = old_part
                .split(',')
                .next()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(1);
            current = Some(Hunk {
                old_start,
                lines: Vec::new(),
            });
            continue;
        }
        let Some(h) = current.as_mut() else {
            continue; // preamble (---/+++/diff/index) before the first hunk
        };
        match line.as_bytes().first() {
            Some(b'+') => h.lines.push((Op::Add, line[1..].to_string())),
            Some(b'-') => h.lines.push((Op::Remove, line[1..].to_string())),
            Some(b' ') => h.lines.push((Op::Context, line[1..].to_string())),
            Some(b'\\') => {} // "\ No newline at end of file"
            None => h.lines.push((Op::Context, String::new())),
            _ => h.lines.push((Op::Context, line.to_string())),
        }
    }
    if let Some(h) = current.take() {
        hunks.push(h);
    }
    if hunks.is_empty() {
        return Err(EnclaveError::other("patch contains no @@ hunks"));
    }

    let mut out: Vec<String> = Vec::new();
    let mut cursor = 0usize; // next original line not yet copied (0-based)
    for h in &hunks {
        let start = h.old_start.saturating_sub(1);
        if start < cursor {
            return Err(EnclaveError::other("overlapping or out-of-order hunks"));
        }
        if start > orig_lines.len() {
            return Err(EnclaveError::other("hunk starts past end of file"));
        }
        while cursor < start {
            out.push(orig_lines[cursor].to_string());
            cursor += 1;
        }
        for (op, text) in &h.lines {
            match op {
                Op::Add => out.push(text.clone()),
                Op::Context | Op::Remove => {
                    let actual = orig_lines.get(cursor).copied().unwrap_or("");
                    if actual != text {
                        return Err(EnclaveError::other(format!(
                            "hunk context mismatch at line {}: expected {:?}, found {:?}",
                            cursor + 1,
                            text,
                            actual
                        )));
                    }
                    if matches!(op, Op::Context) {
                        out.push(actual.to_string());
                    }
                    cursor += 1;
                }
            }
        }
    }
    while cursor < orig_lines.len() {
        out.push(orig_lines[cursor].to_string());
        cursor += 1;
    }
    Ok(out.join("\n"))
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
            let offset = args["offset"].as_u64().map(|v| v as usize);
            let limit = args["limit"].as_u64().map(|v| v as usize);
            let (text, truncated) = if offset.is_some() || limit.is_some() {
                let full = String::from_utf8_lossy(&data);
                let lines: Vec<&str> = full.lines().collect();
                let start = offset.unwrap_or(1).max(1) - 1;
                let end = match limit {
                    Some(l) => (start + l).min(lines.len()),
                    None => lines.len(),
                };
                let body = lines
                    .get(start..end)
                    .unwrap_or(&[])
                    .iter()
                    .enumerate()
                    .map(|(i, line)| format!("{:>5}  {}", start + i + 1, line))
                    .collect::<Vec<_>>()
                    .join("\n");
                cap(body.as_bytes(), ctx.max_output_bytes)
            } else {
                cap(&data, ctx.max_output_bytes)
            };
            let text = if truncated {
                format!("{text}\n[truncated at {} bytes]", ctx.max_output_bytes)
            } else {
                text
            };
            Ok(ToolOutcome { text, change: None })
        }
        "glob" => {
            let pattern = arg_str("pattern");
            if pattern.is_empty() {
                return Err(EnclaveError::other("glob requires a 'pattern'"));
            }
            let raw = arg_str("path");
            let root = if raw.is_empty() {
                ctx.workspace.clone()
            } else {
                resolve_in_workspace(&ctx.workspace, &raw)?
            };
            let mut files = Vec::new();
            walk_files(&root, &mut files);
            let mut matches: Vec<String> = files
                .iter()
                .filter_map(|p| {
                    let rel = relative_label(&root, p);
                    let name = p.file_name().map(|n| n.to_string_lossy().into_owned());
                    let hit = wildcard_match(&pattern, &rel)
                        || name.map(|n| wildcard_match(&pattern, &n)).unwrap_or(false);
                    if hit {
                        Some(rel)
                    } else {
                        None
                    }
                })
                .collect();
            matches.sort();
            let text = if matches.is_empty() {
                format!("no files match '{pattern}'")
            } else {
                let total = matches.len();
                matches.truncate(200);
                let mut body = matches.join("\n");
                if total > 200 {
                    body.push_str(&format!("\n… {} more matches (narrow the pattern)", total - 200));
                }
                body
            };
            Ok(ToolOutcome { text, change: None })
        }
        "grep" => {
            let pattern = arg_str("pattern");
            if pattern.is_empty() {
                return Err(EnclaveError::other("grep requires a 'pattern'"));
            }
            let re = Regex::new(&pattern)
                .map_err(|e| EnclaveError::other(format!("invalid regex: {e}")))?;
            let raw = arg_str("path");
            let root = if raw.is_empty() {
                ctx.workspace.clone()
            } else {
                resolve_in_workspace(&ctx.workspace, &raw)?
            };
            let file_glob = arg_str("glob");
            let mut files = Vec::new();
            walk_files(&root, &mut files);
            let mut out: Vec<String> = Vec::new();
            'files: for p in &files {
                let rel = relative_label(&root, p);
                if !file_glob.is_empty() && !wildcard_match(&file_glob, &rel) {
                    continue;
                }
                let data = match std::fs::read(p) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                if data.contains(&0) {
                    continue; // skip binary files
                }
                let text = match std::str::from_utf8(&data) {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                for (i, line) in text.lines().enumerate() {
                    if re.is_match(line) {
                        out.push(format!("{rel}:{}: {}", i + 1, line.trim_end()));
                        if out.len() >= 200 {
                            break 'files;
                        }
                    }
                }
            }
            let text = if out.is_empty() {
                format!("no matches for /{pattern}/")
            } else {
                out.join("\n")
            };
            let (text, _) = cap(text.as_bytes(), ctx.max_output_bytes);
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
        "apply_patch" => {
            let path = resolve_in_workspace(&ctx.workspace, &arg_str("path"))?;
            let patch = arg_str("patch");
            if patch.trim().is_empty() {
                return Err(EnclaveError::other("apply_patch requires a 'patch'"));
            }
            let old = std::fs::read_to_string(&path)
                .map_err(|e| EnclaveError::other(format!("cannot read {}: {e}", path.display())))?;
            let new = apply_unified(&old, &patch)
                .map_err(|e| EnclaveError::other(format!("patch failed: {e}")))?;
            std::fs::write(&path, &new)?;
            let d = diff::lines(&old, &new);
            let (added, removed) = diff::stats(&d);
            let text = format!(
                "patched {} (+{} \u{2212}{})\n{}",
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
            let out = shell::run_sandboxed(&command, timeout, ctx.max_output_bytes, ctx.sandbox.as_ref()).await?;
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
        "todo" => {
            let items: Vec<TodoItem> = args["items"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| {
                            let text = v["text"].as_str()?.trim().to_string();
                            if text.is_empty() {
                                return None;
                            }
                            let status = v["status"].as_str().unwrap_or("pending").to_string();
                            Some(TodoItem { text, status })
                        })
                        .collect()
                })
                .unwrap_or_default();
            if items.is_empty() {
                return Err(EnclaveError::other("todo requires a non-empty 'items' array"));
            }
            if let Some(shared) = &ctx.todos {
                if let Ok(mut guard) = shared.lock() {
                    *guard = items.clone();
                }
            }
            let rendered = items
                .iter()
                .map(|t| {
                    let mark = match t.status.as_str() {
                        "done" => "[x]",
                        "in_progress" => "[~]",
                        _ => "[ ]",
                    };
                    format!("{mark} {}", t.text)
                })
                .collect::<Vec<_>>()
                .join("\n");
            Ok(ToolOutcome {
                text: format!("task list ({} items):\n{rendered}", items.len()),
                change: None,
            })
        }
        "question" => {
            let question = arg_str("question");
            if question.is_empty() {
                return Err(EnclaveError::other("question requires a 'question'"));
            }
            let options: Vec<String> = args["options"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            match &ctx.ask {
                Some(ask) => Ok(ToolOutcome {
                    text: ask(&question, &options).await?,
                    change: None,
                }),
                None => Ok(ToolOutcome {
                    text: format!(
                        "[question asked: {question}] \
                         (no interactive input available — answer in your next message)"
                    ),
                    change: None,
                }),
            }
        }
        other => {
            if other.starts_with("mcp__") {
                let registry = ctx.mcp.as_ref().ok_or_else(|| {
                    EnclaveError::other(format!("mcp tool '{other}' has no connected server"))
                })?;
                let args: serde_json::Value = serde_json::from_str(&call.arguments)
                    .unwrap_or_else(|_| serde_json::json!({}));
                return Ok(ToolOutcome {
                    text: registry.call(other, args)?,
                    change: None,
                });
            }
            Err(EnclaveError::other(format!("unknown tool '{other}'")))
        }
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
        assert_eq!(base.len(), 11);
        assert!(base.iter().all(|d| !d.name.is_empty()));
        assert!(base.iter().any(|d| d.name == "edit_file"));
        assert!(base.iter().any(|d| d.name == "apply_patch"));
        assert!(base.iter().any(|d| d.name == "glob"));
        assert!(base.iter().any(|d| d.name == "grep"));
        assert!(base.iter().any(|d| d.name == "todo"));
        assert!(base.iter().any(|d| d.name == "question"));
        assert!(base.iter().any(|d| d.name == "remember"));
        let with = defs(true);
        assert_eq!(with.len(), 12);
        assert_eq!(with[11].name, "delegate");
    }

    fn ctx_at(ws: &Path) -> ToolContext {
        ToolContext {
            workspace: ws.to_path_buf(),
            shell_timeout_secs: 5,
            max_output_bytes: 8192,
            ..Default::default()
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

    #[tokio::test]
    async fn todo_records_and_renders_items() {
        let dir = tempfile::tempdir().unwrap();
        let shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let ctx = ToolContext {
            todos: Some(shared.clone()),
            ..ctx_at(dir.path())
        };
        let call = ToolCall {
            id: "1".into(),
            name: "todo".into(),
            arguments: serde_json::json!({"items":[
                {"text":"read the code","status":"done"},
                {"text":"write the fix","status":"in_progress"}
            ]})
            .to_string(),
        };
        let out = execute_detailed(&call, &ctx, &mut AllowAll).await.unwrap();
        assert!(out.text.contains("[x] read the code"));
        assert!(out.text.contains("[~] write the fix"));
        assert_eq!(shared.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn question_without_ui_reports_and_does_not_fail() {
        let dir = tempfile::tempdir().unwrap();
        let call = ToolCall {
            id: "1".into(),
            name: "question".into(),
            arguments: serde_json::json!({"question":"which file?","options":["a","b"]}).to_string(),
        };
        let out = execute_detailed(&call, &ctx_at(dir.path()), &mut AllowAll)
            .await
            .unwrap();
        assert!(out.text.contains("which file?"));
    }

    #[test]
    fn apply_unified_applies_hunks_and_rejects_mismatch() {
        let original = "one\ntwo\nthree\n";
        let patch = "@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three";
        let out = apply_unified(original, patch).unwrap();
        assert_eq!(out, "one\nTWO\nthree\n");

        assert!(apply_unified(original, "@@ -1,1 +1,1 @@\n-zzz\n+x").is_err());
        assert!(apply_unified(original, "no hunks here").is_err());
    }
}
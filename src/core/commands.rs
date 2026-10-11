//! Local custom slash commands and message references.
//!
//! Custom commands are Markdown files with optional front-matter:
//!
//! ```markdown
//! ---
//! description: Review the staged changes
//! agent: build
//! ---
//! Review the diff for bugs and privacy leaks. Focus on: $ARGUMENTS
//! ```
//!
//! They are read from `<config_dir>/commands/*.md` (global) and
//! `<workspace>/.enclave/commands/*.md` (project, overrides global by name).
//! Everything is resolved on disk — no network access, ever.
//!
//! This module also resolves `@path` file references typed in a message,
//! turning them into text/image attachments.

use std::path::{Path, PathBuf};

use crate::core::attachment::Attachment;
use crate::core::builtin_tools::list_files;

/// Subdirectory (under the config dir and `.enclave/`) holding command files.
pub const COMMANDS_SUBDIR: &str = "commands";

/// A user-defined slash command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomCommand {
    pub name: String,
    pub description: String,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub template: String,
}

/// Project-level commands directory: `<workspace>/.enclave/commands`.
pub fn project_dir(workspace: &Path) -> PathBuf {
    workspace.join(".enclave").join(COMMANDS_SUBDIR)
}

/// Global commands directory: `<config_dir>/commands`.
pub fn global_dir(config_dir: &Path) -> PathBuf {
    config_dir.join(COMMANDS_SUBDIR)
}

/// Parse one command file (front-matter + body).
pub fn parse(name: &str, raw: &str) -> CustomCommand {
    let mut description = String::new();
    let mut agent = None;
    let mut model = None;
    let mut body = raw;

    if let Some(rest) = raw.strip_prefix("---") {
        let rest = rest.trim_start_matches(['\r', '\n']);
        if let Some(end) = rest.find("\n---") {
            let front = &rest[..end];
            for line in front.lines() {
                let Some((key, value)) = line.split_once(':') else {
                    continue;
                };
                let value = value.trim().to_string();
                match key.trim() {
                    "description" => description = value,
                    "agent" => agent = Some(value),
                    "model" => model = Some(value),
                    _ => {}
                }
            }
            let after = &rest[end + 4..];
            body = after.trim_start_matches(['\r', '\n']);
        }
    }

    CustomCommand {
        name: name.to_string(),
        description,
        agent,
        model,
        template: body.trim_end().to_string(),
    }
}

fn read_dir_commands(dir: &Path, into: &mut Vec<CustomCommand>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Ok(raw) = std::fs::read_to_string(&path) {
            let cmd = parse(stem, &raw);
            if let Some(existing) = into.iter_mut().find(|c| c.name == cmd.name) {
                *existing = cmd;
            } else {
                into.push(cmd);
            }
        }
    }
}

/// Load all custom commands (global first, then project — project wins).
pub fn load_all(workspace: &Path, config_dir: &Path) -> Vec<CustomCommand> {
    let mut commands = Vec::new();
    read_dir_commands(&global_dir(config_dir), &mut commands);
    read_dir_commands(&project_dir(workspace), &mut commands);
    commands.sort_by(|a, b| a.name.cmp(&b.name));
    commands
}

/// Find a command by name.
pub fn find<'a>(commands: &'a [CustomCommand], name: &str) -> Option<&'a CustomCommand> {
    commands.iter().find(|c| c.name == name)
}

/// Expand a command template: `$ARGUMENTS` and positional `$1`..`$9`.
pub fn expand(template: &str, args: &str) -> String {
    let positional: Vec<&str> = args.split_whitespace().collect();
    let mut out = template.replace("$ARGUMENTS", args);
    for i in (1..=9).rev() {
        let placeholder = format!("${i}");
        let value = positional.get(i - 1).copied().unwrap_or("");
        out = out.replace(&placeholder, value);
    }
    out
}

/// Result of resolving `@refs` in a message.
pub struct FileRefs {
    /// The message text with resolved `@refs` removed.
    pub text: String,
    /// Attachments produced from the references.
    pub attachments: Vec<Attachment>,
    /// Names that were resolved (for display).
    pub names: Vec<String>,
}

fn resolve_ref(workspace: &Path, token: &str) -> Option<PathBuf> {
    if token.is_empty() {
        return None;
    }
    let direct = workspace.join(token);
    if direct.is_file() {
        return Some(direct);
    }
    let files = list_files(workspace);
    let rel = |p: &PathBuf| {
        p.strip_prefix(workspace)
            .unwrap_or(p)
            .to_string_lossy()
            .replace('\\', "/")
    };
    if let Some(p) = files.iter().find(|p| rel(p) == token) {
        return Some(p.clone());
    }
    if let Some(p) = files
        .iter()
        .find(|p| p.file_name().and_then(|f| f.to_str()) == Some(token))
    {
        return Some(p.clone());
    }
    files.into_iter().find(|p| rel(p).ends_with(token))
}

/// Resolve `@path` tokens into attachments, stripping them from the text.
pub fn resolve_file_refs(text: &str, workspace: &Path) -> FileRefs {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut attachments = Vec::new();
    let mut names = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '@' && (i == 0 || chars[i - 1].is_whitespace()) {
            let mut j = i + 1;
            while j < chars.len() && !chars[j].is_whitespace() {
                j += 1;
            }
            let token: String = chars[i + 1..j].iter().collect();
            if let Some(path) = resolve_ref(workspace, &token) {
                if let Ok(att) = Attachment::from_file(&path) {
                    names.push(att.name.clone());
                    attachments.push(att);
                    i = j;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    let mut cleaned = out.trim().to_string();
    if cleaned.is_empty() && !attachments.is_empty() {
        cleaned = "(attached files)".to_string();
    }
    FileRefs {
        text: cleaned,
        attachments,
        names,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parses_frontmatter_and_expands_args() {
        let raw = "---\ndescription: Deploy\nagent: build\nmodel: gpt-4o\n---\nDeploy $1 to $2. All: $ARGUMENTS";
        let cmd = parse("deploy", raw);
        assert_eq!(cmd.description, "Deploy");
        assert_eq!(cmd.agent.as_deref(), Some("build"));
        assert_eq!(cmd.model.as_deref(), Some("gpt-4o"));
        let expanded = expand(&cmd.template, "prod eu-west");
        assert_eq!(expanded, "Deploy prod to eu-west. All: prod eu-west");
    }

    #[test]
    fn loads_global_then_project_with_override() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("ws");
        let cfg = tmp.path().join("cfg");
        fs::create_dir_all(project_dir(&ws)).unwrap();
        fs::create_dir_all(global_dir(&cfg)).unwrap();
        fs::write(global_dir(&cfg).join("review.md"), "global body").unwrap();
        fs::write(global_dir(&cfg).join("only-global.md"), "g").unwrap();
        fs::write(project_dir(&ws).join("review.md"), "project body").unwrap();

        let cmds = load_all(&ws, &cfg);
        let review = find(&cmds, "review").unwrap();
        assert_eq!(review.template, "project body");
        assert!(find(&cmds, "only-global").is_some());
    }

    #[test]
    fn resolves_file_ref_into_attachment_and_strips_token() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path();
        fs::create_dir_all(ws.join("src")).unwrap();
        fs::write(ws.join("src/notes.md"), "hello notes").unwrap();

        let refs = resolve_file_refs("please read @src/notes.md and summarize", ws);
        assert_eq!(refs.attachments.len(), 1);
        assert_eq!(refs.names, vec!["notes.md".to_string()]);
        assert_eq!(refs.text, "please read  and summarize");
    }

    #[test]
    fn unmatched_ref_is_left_in_place() {
        let tmp = tempfile::tempdir().unwrap();
        let refs = resolve_file_refs("mail me at @nobody", tmp.path());
        assert!(refs.attachments.is_empty());
        assert!(refs.text.contains("@nobody"));
    }
}

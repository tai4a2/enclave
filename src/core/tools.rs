//! Tool execution: the AI *proposes* shell commands, the human *approves*.
//!
//! Security model:
//! - Proposals are fenced ```bash blocks in the assistant reply.
//! - Nothing ever runs without an explicit interactive confirmation.
//! - Every run has a hard timeout and the process is killed on drop.
//! - Output is truncated before display and before it enters the history
//!   (what enters the history may later be sent to the provider).
//! - `--no-tools` (or `tools.enabled = false`) disables the feature entirely.

use std::path::PathBuf;
use std::time::Duration;

use tokio::process::Command;

use crate::config::SandboxMode;
use crate::error::Result;

/// Languages accepted inside fenced blocks.
const SHELL_LANGS: &[&str] = &["bash", "sh", "shell", "zsh"];

/// A shell command proposed by the assistant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub lang: String,
    pub command: String,
}

/// Result of an executed command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    pub stdout: String,
    pub stderr: String,
    /// Process exit code, `None` if it was killed (timeout).
    pub code: Option<i32>,
    pub timed_out: bool,
    pub truncated: bool,
}

impl ToolOutput {
    /// Compact human-readable rendering of the output.
    pub fn render(&self) -> String {
        let mut out = String::new();
        if !self.stdout.is_empty() {
            out.push_str(&self.stdout);
        }
        if !self.stderr.is_empty() {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&self.stderr);
        }
        if self.timed_out {
            out.push_str("\n[command timed out and was killed]");
        } else {
            out.push_str(&format!("\n[exit code: {}]", self.code.unwrap_or(-1)));
        }
        if self.truncated {
            out.push_str("\n[output truncated]");
        }
        out
    }

    /// History-persisted form (also fed back to the provider on the next turn).
    pub fn as_tool_message(&self, command: &str) -> String {
        format!("[tool] $ {}\n{}\n{}", command, self.render(), "[/tool]")
    }
}

/// Extract shell command proposals from an assistant reply.
///
/// Recognizes fenced blocks tagged `bash`, `sh`, `shell` or `zsh`. An
/// unclosed fence contributes nothing. Order is preserved.
pub fn extract_proposals(text: &str) -> Vec<Proposal> {
    let mut proposals = Vec::new();
    let mut lines = text.lines().peekable();

    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        let Some(fence) = trimmed.strip_prefix("```") else {
            continue;
        };
        let lang = fence.trim().to_lowercase();
        if !SHELL_LANGS.contains(&lang.as_str()) {
            continue;
        }

        let mut body: Vec<&str> = Vec::new();
        let mut closed = false;
        for l in lines.by_ref() {
            if l.trim_start().starts_with("```") {
                closed = true;
                break;
            }
            body.push(l);
        }
        if !closed {
            continue; // unclosed fence: never propose
        }
        let command = body.join("\n").trim().to_string();
        if command.is_empty() {
            continue;
        }
        proposals.push(Proposal { lang, command });
    }
    proposals
}

/// Truncate a byte string at a UTF-8 character boundary.
fn truncate_utf8(data: &[u8], max_bytes: usize) -> (String, bool) {
    if data.len() <= max_bytes {
        return (String::from_utf8_lossy(data).into_owned(), false);
    }
    let mut end = max_bytes;
    while end > 0 && std::str::from_utf8(&data[..end]).is_err() {
        end -= 1;
    }
    (
        String::from_utf8_lossy(&data[..end]).into_owned(),
        true,
    )
}

/// OS-level sandbox settings for approved shell commands.
#[derive(Debug, Clone)]
pub struct Sandbox {
    pub mode: SandboxMode,
    pub workspace: PathBuf,
}

impl Sandbox {
    /// Create a sandbox for commands run with `workspace` as the writable root.
    pub fn new(mode: SandboxMode, workspace: impl Into<PathBuf>) -> Self {
        Self {
            mode,
            workspace: workspace.into(),
        }
    }

    /// The effective mode on this platform (`Auto` = filesystem jail only on
    /// macOS, where `sandbox-exec` is available; elsewhere `Off`).
    pub fn effective(&self) -> SandboxMode {
        match self.mode {
            SandboxMode::Auto => {
                if cfg!(target_os = "macos") {
                    SandboxMode::Fs
                } else {
                    SandboxMode::Off
                }
            }
            other => other,
        }
    }

    /// Whether this sandbox actually restricts anything on this platform.
    pub fn is_active(&self) -> bool {
        cfg!(target_os = "macos") && self.effective() != SandboxMode::Off
    }

    /// Build the macOS SBPL profile string.
    pub fn profile(&self) -> String {
        let mut p = String::new();
        p.push_str("(version 1)\n");
        p.push_str("(deny default)\n");
        p.push_str("(allow process*)\n");
        p.push_str("(allow sysctl-read)\n");
        p.push_str("(allow mach-lookup)\n");
        p.push_str("(allow file-read*)\n");
        // Writes are allowed only inside the workspace and temp directories.
        for dir in sandbox_write_dirs(&self.workspace) {
            p.push_str(&format!(
                "(allow file-write* (subpath \"{}\"))\n",
                escape_sbpl(&dir)
            ));
        }
        p.push_str("(allow file-write* (regex #\"^/dev/(null|stdout|stderr)$\"))\n");
        match self.effective() {
            SandboxMode::Strict => p.push_str("(deny network*)\n"),
            _ => p.push_str("(allow network*)\n"),
        }
        p
    }
}

/// Directory prefixes where a sandboxed command may write.
fn sandbox_write_dirs(workspace: &std::path::Path) -> Vec<String> {
    let mut dirs = vec![workspace.display().to_string()];
    if let Ok(tmp) = std::env::var("TMPDIR") {
        if !tmp.is_empty() {
            dirs.push(tmp);
        }
    }
    for extra in [
        "/tmp",
        "/private/tmp",
        "/var/folders",
        "/private/var/folders",
    ] {
        dirs.push(extra.to_string());
    }
    dirs
}

/// Escape a path for embedding in an SBPL quoted string.
fn escape_sbpl(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Run a proposed command under `sh -c` with a hard timeout.
///
/// The child process is killed if the timeout elapses or if the returned
/// future is dropped. Output is truncated to `max_output_bytes` per stream.
pub async fn run(command: &str, timeout: Duration, max_output_bytes: usize) -> Result<ToolOutput> {
    run_with(
        "sh",
        &["-c", command],
        timeout,
        max_output_bytes,
    )
    .await
}

/// Run a command inside the given sandbox (when one is active on this
/// platform), falling back to a plain `sh -c` run otherwise.
pub async fn run_sandboxed(
    command: &str,
    timeout: Duration,
    max_output_bytes: usize,
    sandbox: Option<&Sandbox>,
) -> Result<ToolOutput> {
    match sandbox {
        Some(sb) if sb.is_active() => {
            let profile = sb.profile();
            run_with(
                "sandbox-exec",
                &["-p", &profile, "sh", "-c", command],
                timeout,
                max_output_bytes,
            )
            .await
        }
        _ => run(command, timeout, max_output_bytes).await,
    }
}

async fn run_with(
    program: &str,
    args: &[&str],
    timeout: Duration,
    max_output_bytes: usize,
) -> Result<ToolOutput> {
    let child = Command::new(program)
        .args(args)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null())
        .spawn()?;

    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(output)) => {
            let (stdout, out_trunc) = truncate_utf8(&output.stdout, max_output_bytes);
            let (stderr, err_trunc) = truncate_utf8(&output.stderr, max_output_bytes);
            Ok(ToolOutput {
                stdout,
                stderr,
                code: output.status.code(),
                timed_out: false,
                truncated: out_trunc || err_trunc,
            })
        }
        Ok(Err(e)) => Err(e.into()),
        Err(_elapsed) => Ok(ToolOutput {
            stdout: String::new(),
            stderr: String::new(),
            code: None,
            timed_out: true,
            truncated: false,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_finds_bash_blocks_in_order() {
        let text = "before\n```bash\necho one\n```\nmid\n```sh\nls -la\npwd\n```\nafter";
        let p = extract_proposals(text);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].command, "echo one");
        assert_eq!(p[1].command, "ls -la\npwd");
    }

    #[test]
    fn extract_ignores_other_languages_and_unclosed_fences() {
        let text = "```python\nprint('hi')\n```\n```bash\necho closed\n```\n```bash\necho unclosed";
        let p = extract_proposals(text);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].command, "echo closed");
    }

    #[test]
    fn extract_ignores_empty_blocks_and_plain_text() {
        assert!(extract_proposals("no code here").is_empty());
        assert!(extract_proposals("```bash\n```\n").is_empty());
        assert!(extract_proposals("").is_empty());
    }

    #[test]
    fn extract_accepts_lang_variants() {
        let text = "```shell\ntrue\n```";
        assert_eq!(extract_proposals(text).len(), 1);
        let text = "```ZSH\ntrue\n```";
        assert_eq!(extract_proposals(text).len(), 1);
    }

    #[tokio::test]
    async fn run_captures_output_and_exit_code() {
        let out = run("echo hello; echo oops >&2; exit 3", Duration::from_secs(10), 8192)
            .await
            .unwrap();
        assert_eq!(out.stdout.trim(), "hello");
        assert_eq!(out.stderr.trim(), "oops");
        assert_eq!(out.code, Some(3));
        assert!(!out.timed_out);
    }

    #[tokio::test]
    async fn run_truncates_huge_output() {
        let out = run("yes X | head -c 100000", Duration::from_secs(10), 1000)
            .await
            .unwrap();
        assert!(out.truncated);
        assert!(out.stdout.len() <= 1000 + 4); // lossy replacement may add a char
    }

    #[tokio::test]
    async fn run_timeout_kills_process() {
        let start = std::time::Instant::now();
        let out = run("sleep 30", Duration::from_millis(400), 8192)
            .await
            .unwrap();
        assert!(out.timed_out);
        assert!(out.code.is_none());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn run_utf8_truncation_is_boundary_safe() {
        // 'à' is 2 bytes; force a cut inside a multibyte char.
        let out = run("printf 'ààààà'", Duration::from_secs(10), 4)
            .await
            .unwrap();
        assert!(out.truncated);
        assert!(std::str::from_utf8(out.stdout.as_bytes()).is_ok());
    }

    #[test]
    fn tool_message_format_is_self_describing() {
        let out = ToolOutput {
            stdout: "hi".into(),
            stderr: String::new(),
            code: Some(0),
            timed_out: false,
            truncated: false,
        };
        let msg = out.as_tool_message("echo hi");
        assert!(msg.starts_with("[tool] $ echo hi"));
        assert!(msg.ends_with("[/tool]"));
        assert!(msg.contains("exit code: 0"));
    }

    #[test]
    fn sandbox_effective_mode_follows_the_platform() {
        let auto = Sandbox::new(SandboxMode::Auto, "/tmp/ws");
        if cfg!(target_os = "macos") {
            assert_eq!(auto.effective(), SandboxMode::Fs);
            assert!(auto.is_active());
        } else {
            assert_eq!(auto.effective(), SandboxMode::Off);
            assert!(!auto.is_active());
        }
        assert_eq!(
            Sandbox::new(SandboxMode::Off, "/tmp/ws").effective(),
            SandboxMode::Off
        );
        assert_eq!(
            Sandbox::new(SandboxMode::Strict, "/tmp/ws").effective(),
            SandboxMode::Strict
        );
    }

    #[test]
    fn sandbox_profile_scopes_writes_and_network() {
        let sb = Sandbox::new(SandboxMode::Fs, "/Users/me/project");
        let p = sb.profile();
        assert!(p.contains("(deny default)"));
        assert!(p.contains("(allow file-read*)"));
        assert!(p.contains("(allow file-write* (subpath \"/Users/me/project\"))"));
        assert!(p.contains("(allow network*)"));
        assert!(!p.contains("(deny network*)"));

        let strict = Sandbox::new(SandboxMode::Strict, "/Users/me/project");
        assert!(strict.profile().contains("(deny network*)"));
    }

    #[tokio::test]
    async fn run_sandboxed_off_matches_plain_run() {
        let plain = run("echo sandbox-check", Duration::from_secs(10), 8192)
            .await
            .unwrap();
        let sandboxless = run_sandboxed("echo sandbox-check", Duration::from_secs(10), 8192, None)
            .await
            .unwrap();
        assert_eq!(plain.stdout, sandboxless.stdout);

        let off = Sandbox::new(SandboxMode::Off, std::env::temp_dir());
        let out = run_sandboxed("echo sandbox-check", Duration::from_secs(10), 8192, Some(&off))
            .await
            .unwrap();
        assert_eq!(out.stdout.trim(), "sandbox-check");
    }

    #[tokio::test]
    async fn run_sandboxed_allows_writing_inside_workspace() {
        // Only meaningful on macOS where sandbox-exec is active; elsewhere the
        // sandbox is a no-op but the command must still run.
        let ws = std::env::temp_dir().join(format!("enclave-sbx-{}", std::process::id()));
        std::fs::create_dir_all(&ws).unwrap();
        let sb = Sandbox::new(SandboxMode::Auto, &ws);
        if sb.is_active() {
            let cmd = format!("echo hi > {}", ws.join("out.txt").display());
            let out = run_sandboxed(&cmd, Duration::from_secs(10), 8192, Some(&sb))
                .await
                .unwrap();
            assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
            assert!(ws.join("out.txt").exists());
        }
        let _ = std::fs::remove_dir_all(&ws);
    }
}
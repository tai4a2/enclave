//! Auto verification loop.
//!
//! After the assistant edits files, Enclave can run the project's own checks
//! (tests, lint, typecheck) locally in the sandbox and feed failures back to
//! the model so it fixes them by itself. Detection is intentionally simple and
//! offline: it looks at a handful of well-known project files.
//!
//! Nothing here sends code anywhere — the command runs on this machine, in the
//! command sandbox, exactly like any other `run_shell` in agentic mode.

use std::path::Path;
use std::time::Duration;

use crate::core::tools::{self, Sandbox};
use crate::error::Result;

/// A verification command chosen for a workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyCommand {
    /// The shell command to run.
    pub command: String,
    /// Where the choice came from (for display).
    pub source: String,
}

/// The outcome of running a verification command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub command: String,
    pub passed: bool,
    pub code: Option<i32>,
    pub summary: String,
    pub output: String,
    pub timed_out: bool,
}

/// Detect a sensible verification command for `workspace`, if any.
///
/// Order of preference: Rust (cargo) → Node (npm/pnpm/yarn) → Python (pytest)
/// → Go → Makefile. Returns `None` when nothing recognizable is found.
pub fn detect(workspace: &Path) -> Option<VerifyCommand> {
    let has = |name: &str| workspace.join(name).exists();

    if has("Cargo.toml") {
        return Some(VerifyCommand {
            command: "cargo test --quiet".into(),
            source: "Cargo.toml".into(),
        });
    }
    if has("package.json") {
        let runner = if has("pnpm-lock.yaml") {
            "pnpm"
        } else if has("yarn.lock") {
            "yarn"
        } else {
            "npm"
        };
        // Only propose it when a test script exists in package.json.
        if let Ok(text) = std::fs::read_to_string(workspace.join("package.json")) {
            if text.contains("\"test\"") {
                return Some(VerifyCommand {
                    command: format!("{runner} test"),
                    source: "package.json (scripts.test)".into(),
                });
            }
        }
    }
    if has("pyproject.toml") || has("pytest.ini") || has("setup.cfg") || has("tox.ini") {
        return Some(VerifyCommand {
            command: "pytest -q".into(),
            source: "pytest config".into(),
        });
    }
    if has("go.mod") {
        return Some(VerifyCommand {
            command: "go test ./...".into(),
            source: "go.mod".into(),
        });
    }
    if has("Makefile") {
        if let Ok(text) = std::fs::read_to_string(workspace.join("Makefile")) {
            if text.contains("\ntest:") || text.starts_with("test:") {
                return Some(VerifyCommand {
                    command: "make test".into(),
                    source: "Makefile (test target)".into(),
                });
            }
        }
    }
    None
}

/// Run a verification command in the workspace sandbox.
pub async fn run(
    workspace: &Path,
    command: &str,
    timeout_secs: u64,
    max_output_bytes: usize,
    sandbox: Option<&Sandbox>,
) -> Result<VerifyReport> {
    // `run_sandboxed` runs `sh -c` in the process cwd, so change into the
    // workspace first (single-quoted to survive spaces).
    let dir = workspace.display().to_string().replace('\'', "'\\''");
    let wrapped = format!("cd '{dir}' && {command}");
    let out = tools::run_sandboxed(
        &wrapped,
        Duration::from_secs(timeout_secs.max(1)),
        max_output_bytes.max(2048),
        sandbox,
    )
    .await?;

    let passed = out.code == Some(0) && !out.timed_out;
    let summary = if out.timed_out {
        format!("verification timed out after {timeout_secs}s")
    } else if passed {
        "verification passed".to_string()
    } else {
        match out.code {
            Some(code) => format!("verification failed (exit {code})"),
            None => "verification failed (no exit code)".to_string(),
        }
    };
    Ok(VerifyReport {
        command: command.to_string(),
        passed,
        code: out.code,
        summary,
        output: out.render(),
        timed_out: out.timed_out,
    })
}

/// A short message to hand back to the model when verification fails.
pub fn feedback(report: &VerifyReport) -> String {
    format!(
        "[verify] `{}` {}\n{}",
        report.command, report.summary, report.output
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_cargo_projects() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]").unwrap();
        let cmd = detect(dir.path()).unwrap();
        assert!(cmd.command.contains("cargo test"));
        assert_eq!(cmd.source, "Cargo.toml");
    }

    #[test]
    fn detects_node_test_script() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            "{\"scripts\":{\"test\":\"jest\"}}",
        )
        .unwrap();
        let cmd = detect(dir.path()).unwrap();
        assert_eq!(cmd.command, "npm test");
    }

    #[test]
    fn ignores_node_without_test_script() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{\"scripts\":{}}").unwrap();
        assert!(detect(dir.path()).is_none());
    }

    #[test]
    fn detects_pytest_and_go() {
        let py = tempfile::tempdir().unwrap();
        std::fs::write(py.path().join("pyproject.toml"), "[project]").unwrap();
        assert_eq!(detect(py.path()).unwrap().command, "pytest -q");

        let go = tempfile::tempdir().unwrap();
        std::fs::write(go.path().join("go.mod"), "module x").unwrap();
        assert_eq!(detect(go.path()).unwrap().command, "go test ./...");
    }

    #[test]
    fn empty_dir_has_no_command() {
        let dir = tempfile::tempdir().unwrap();
        assert!(detect(dir.path()).is_none());
    }
}

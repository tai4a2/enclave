//! Workspace checkpoints.
//!
//! Before Enclave modifies files it can snapshot the working directory into a
//! private, local *shadow* git repository (never the project's own `.git`).
//! Snapshots let you rewind an experimental change, much like the checkpoints
//! of modern coding agents — but entirely on this machine: no remote, no
//! network, and a neutral `Enclave` commit identity so your personal git
//! identity never leaks into the shadow history.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::{EnclaveError, Result};

/// Paths skipped inside the shadow repository (heavy or irrelevant).
const EXCLUDE: &str = "# written by Enclave — checkpoint exclusions\n\
.git/\n\
node_modules/\n\
target/\n\
dist/\n\
.venv/\n\
venv/\n\
__pycache__/\n\
*.pyc\n\
*.db\n\
*.db-journal\n\
*.db-wal\n\
.DS_Store\n";

/// A recorded snapshot of the workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Abbreviated commit id inside the shadow repository.
    pub id: String,
    /// When it was taken (`YYYY-MM-DD HH:MM`).
    pub when: String,
    /// Human label (e.g. `before edit_file src/main.rs`).
    pub label: String,
}

/// Git-backed, local-only workspace snapshots.
pub struct CheckpointStore {
    workspace: PathBuf,
    git_dir: PathBuf,
    git_ok: bool,
}

impl CheckpointStore {
    /// Create a store rooted at `data_dir` (the shadow repo lives there, never
    /// inside the project) tracking `workspace`.
    pub fn new(workspace: &Path, data_dir: &Path) -> Self {
        let git_ok = Command::new("git")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        Self {
            workspace: workspace.to_path_buf(),
            git_dir: data_dir.join("checkpoints.git"),
            git_ok,
        }
    }

    /// Whether the git binary is available.
    pub fn is_available(&self) -> bool {
        self.git_ok
    }

    /// Location of the shadow repository.
    pub fn git_dir(&self) -> &Path {
        &self.git_dir
    }

    fn run(&self, args: &[&str]) -> Result<std::process::Output> {
        Command::new("git")
            .arg("--git-dir")
            .arg(&self.git_dir)
            .arg("--work-tree")
            .arg(&self.workspace)
            .args(args)
            .output()
            .map_err(|e| EnclaveError::other(format!("git: {e}")))
    }

    fn ensure_init(&self) -> Result<()> {
        if !self.git_ok {
            return Err(EnclaveError::other("git is not installed"));
        }
        if self.git_dir.join("HEAD").exists() {
            return Ok(());
        }
        std::fs::create_dir_all(&self.git_dir)?;
        let out = self.run(&["init", "--quiet"])?;
        if !out.status.success() {
            return Err(EnclaveError::other(format!(
                "git init failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let exclude = self.git_dir.join("info").join("exclude");
        if let Some(parent) = exclude.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&exclude, EXCLUDE)?;
        Ok(())
    }

    /// Record a snapshot. Returns the short id, or `None` when nothing changed
    /// since the last snapshot.
    pub fn snapshot(&self, label: &str) -> Result<Option<String>> {
        self.ensure_init()?;
        let add = self.run(&["add", "-A"])?;
        if !add.status.success() {
            return Err(EnclaveError::other(format!(
                "git add failed: {}",
                String::from_utf8_lossy(&add.stderr).trim()
            )));
        }
        let label = label.trim();
        let label = if label.is_empty() {
            "checkpoint"
        } else {
            label
        };
        let commit = self.run(&[
            "-c",
            "user.name=Enclave",
            "-c",
            "user.email=enclave@localhost",
            "commit",
            "--quiet",
            "--no-verify",
            "-m",
            label,
        ])?;
        if !commit.status.success() {
            // Nothing staged: no changes to record.
            return Ok(None);
        }
        let rev = self.run(&["rev-parse", "--short", "HEAD"])?;
        Ok(Some(
            String::from_utf8_lossy(&rev.stdout).trim().to_string(),
        ))
    }

    /// Most recent snapshots first.
    pub fn list(&self, limit: usize) -> Result<Vec<Checkpoint>> {
        if !self.git_ok || !self.git_dir.join("HEAD").exists() {
            return Ok(Vec::new());
        }
        let n = format!("-n{}", limit.max(1));
        let out = self.run(&[
            "log",
            &n,
            "--date=format:%Y-%m-%d %H:%M",
            "--pretty=format:%h%x1f%ad%x1f%s",
        ])?;
        if !out.status.success() {
            return Ok(Vec::new());
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut items = Vec::new();
        for line in text.lines() {
            let mut parts = line.split('\u{1f}');
            let id = parts.next().unwrap_or("").trim();
            let when = parts.next().unwrap_or("").trim();
            let label = parts.next().unwrap_or("").trim();
            if id.is_empty() {
                continue;
            }
            items.push(Checkpoint {
                id: id.to_string(),
                when: when.to_string(),
                label: label.to_string(),
            });
        }
        Ok(items)
    }

    /// How many snapshots exist.
    pub fn count(&self) -> Result<usize> {
        if !self.git_ok || !self.git_dir.join("HEAD").exists() {
            return Ok(0);
        }
        let out = self.run(&["rev-list", "--count", "HEAD"])?;
        if !out.status.success() {
            return Ok(0);
        }
        Ok(String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .unwrap_or(0))
    }

    /// Rewind the workspace to a snapshot. Keeps history linear and reversible:
    /// the current state is snapshotted first, the snapshot's files are restored,
    /// then the restored state is committed as a new snapshot.
    pub fn restore(&self, id: &str) -> Result<()> {
        self.ensure_init()?;
        let id = id.trim();
        if id.is_empty() {
            return Err(EnclaveError::other("checkpoint id is required"));
        }
        let _ = self.snapshot(&format!("pre-rewind (was {id})"));
        let out = self.run(&["checkout", id, "--", "."])?;
        if !out.status.success() {
            return Err(EnclaveError::other(format!(
                "git checkout failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        // Drop files created since the snapshot (ignored paths are preserved).
        let _ = self.run(&["clean", "-fd"]);
        let _ = self.snapshot(&format!("rewind to {id}"));
        Ok(())
    }

    /// Summary of what a snapshot changed.
    pub fn diff_stat(&self, id: &str) -> Result<String> {
        if !self.git_ok || !self.git_dir.join("HEAD").exists() {
            return Ok(String::new());
        }
        let out = self.run(&["show", "--stat", "--oneline", "--no-color", id])?;
        if !out.status.success() {
            return Err(EnclaveError::other(format!(
                "git show failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }
}

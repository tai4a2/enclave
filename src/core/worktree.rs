//! Git worktrees: a separate working directory per task/branch.
//!
//! Lets Enclave work on several branches of the same repository at once
//! (one worktree per conversation branch) without stashing or switching the
//! main checkout. Everything is local `git`; no network.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{EnclaveError, Result};

/// One registered git worktree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Worktree {
    pub path: PathBuf,
    pub branch: String,
    pub head: String,
}

/// Whether `dir` is inside a git repository.
pub fn is_repo(dir: &Path) -> bool {
    git(dir, &["rev-parse", "--git-dir"]).is_ok()
}

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|e| EnclaveError::other(format!("git not available: {e}")))?;
    if !out.status.success() {
        return Err(EnclaveError::other(format!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Where a worktree for `name` should live by default.
pub fn default_dir(data_dir: &Path, name: &str) -> PathBuf {
    data_dir.join("worktrees").join(name)
}

/// List the repository's worktrees (parses `git worktree list --porcelain`).
pub fn list(repo: &Path) -> Result<Vec<Worktree>> {
    let raw = git(repo, &["worktree", "list", "--porcelain"])?;
    let mut out = Vec::new();
    let mut path: Option<PathBuf> = None;
    let mut branch = String::new();
    let mut head = String::new();
    for line in raw.lines() {
        if let Some(p) = line.strip_prefix("worktree ") {
            path = Some(PathBuf::from(p));
            branch.clear();
            head.clear();
        } else if let Some(h) = line.strip_prefix("HEAD ") {
            head = h.to_string();
        } else if let Some(b) = line.strip_prefix("branch ") {
            branch = b.strip_prefix("refs/heads/").unwrap_or(b).to_string();
        } else if line.trim().is_empty() {
            if let Some(p) = path.take() {
                let branch = if branch.is_empty() {
                    "(detached)".to_string()
                } else {
                    std::mem::take(&mut branch)
                };
                out.push(Worktree {
                    path: p,
                    branch,
                    head: head.clone(),
                });
            }
        }
    }
    if let Some(p) = path.take() {
        let branch = if branch.is_empty() {
            "(detached)".to_string()
        } else {
            branch
        };
        out.push(Worktree {
            path: p,
            branch,
            head,
        });
    }
    Ok(out)
}

/// Create a worktree at `dir` on a new branch `branch` (or an existing one).
pub fn add(repo: &Path, dir: &Path, branch: &str, base: Option<&str>) -> Result<()> {
    if branch.trim().is_empty() {
        return Err(EnclaveError::other("worktree branch name is required"));
    }
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let dir_str = dir.to_string_lossy().to_string();
    let existing = git(repo, &["rev-parse", "--verify", "--quiet", branch]).is_ok();
    let mut args: Vec<&str> = vec!["worktree", "add"];
    if !existing {
        args.push("-b");
        args.push(branch);
    }
    args.push(&dir_str);
    if let Some(base) = base {
        args.push(base);
    }
    git(repo, &args)?;
    Ok(())
}

/// Remove a worktree (and its directory).
pub fn remove(repo: &Path, dir: &Path, force: bool) -> Result<()> {
    let dir_str = dir.to_string_lossy().to_string();
    let mut args: Vec<&str> = vec!["worktree", "remove"];
    if force {
        args.push("--force");
    }
    args.push(&dir_str);
    git(repo, &args)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_repo(dir: &Path) {
        git(dir, &["init", "--quiet"]).unwrap();
        git(dir, &["config", "user.email", "t@localhost"]).unwrap();
        git(dir, &["config", "user.name", "T"]).unwrap();
        std::fs::write(dir.join("f.txt"), "hi").unwrap();
        git(dir, &["add", "."]).unwrap();
        git(dir, &["commit", "--quiet", "-m", "init"]).unwrap();
    }

    #[test]
    fn add_list_and_remove_roundtrip() {
        if git(Path::new("."), &["--version"]).is_err() {
            eprintln!("skipping: git not available");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo);
        assert!(is_repo(&repo));

        let wt = default_dir(tmp.path(), "feature");
        add(&repo, &wt, "feature-x", None).unwrap();
        assert!(wt.join("f.txt").exists());

        let wts = list(&repo).unwrap();
        assert!(wts.iter().any(|w| w.branch == "feature-x"));
        assert!(wts.len() >= 2);

        remove(&repo, &wt, true).unwrap();
        let after = list(&repo).unwrap();
        assert!(!after.iter().any(|w| w.branch == "feature-x"));
    }
}

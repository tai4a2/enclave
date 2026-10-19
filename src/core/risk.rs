//! Local command risk classifier.
//!
//! Pure, offline heuristics that flag destructive or irreversible shell
//! commands *before* they run. It never executes anything and never talks to
//! the network — it just labels a command so the permission layer can always
//! ask (or refuse) and the UI can show a warning badge.
//!
//! The goal is safety-by-default without getting in the way: only clearly
//! dangerous shapes are `High`, common-but-recoverable ones are `Medium`, and
//! everything else is not flagged at all.

/// How dangerous a command looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// Destructive or irreversible (wiping disks, piping a download to a shell…).
    High,
    /// Privileged or history-rewriting but normally recoverable.
    Medium,
}

impl Risk {
    /// Short human label used in badges.
    pub fn label(self) -> &'static str {
        match self {
            Risk::High => "dangerous",
            Risk::Medium => "risky",
        }
    }
}

/// A matched risk with the reason it fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskHit {
    pub risk: Risk,
    pub reason: String,
}

/// Classify a shell command. Returns `None` when nothing notable is found.
pub fn classify(command: &str) -> Option<RiskHit> {
    let hay = command.to_ascii_lowercase();
    let squished: String = hay.split_whitespace().collect::<Vec<_>>().join(" ");
    let no_space: String = squished.replace(' ', "");

    let high = |reason: &str| {
        Some(RiskHit {
            risk: Risk::High,
            reason: reason.to_string(),
        })
    };
    let medium = |reason: &str| {
        Some(RiskHit {
            risk: Risk::Medium,
            reason: reason.to_string(),
        })
    };

    // ---- High: irreversible destruction ---------------------------------
    // rm -rf against the whole filesystem, home, or a bare glob.
    if no_space.contains("rm-rf/")
        || no_space.contains("rm-fr/")
        || no_space.contains("rm-rf~")
        || no_space.contains("rm-rf$home")
        || no_space.contains("rm-rf*")
        || no_space.contains("rm-rf.")
        || squished.contains("--no-preserve-root")
    {
        return high("rm -rf on a system/home/glob path");
    }
    if squished.contains("dd ") && squished.contains("of=/dev/") {
        return high("dd writing to a raw device");
    }
    if squished.starts_with("mkfs") || squished.contains(" mkfs") {
        return high("mkfs formatting a filesystem");
    }
    if no_space.contains(":(){:|:&};:") || no_space.contains(":(){:|:&}") {
        return high("fork bomb");
    }
    if squished.contains("> /dev/sd") || squished.contains("> /dev/disk") {
        return high("overwriting a raw disk device");
    }
    if squished.contains("shutdown") || squished.contains("reboot") || squished.contains("poweroff")
    {
        return high("powering off / rebooting the machine");
    }
    if no_space.contains("sudo%rm") {
        return high("sudo rm");
    }
    // Download piped straight into a shell.
    for shell in ["sh", "bash", "zsh"] {
        if no_space.contains(&format!("|{shell}"))
            && (squished.contains("curl") || squished.contains("wget"))
        {
            return high("piping a download directly into a shell");
        }
    }
    if no_space.starts_with("eval$(curl") || no_space.starts_with("eval$(wget") {
        return high("eval of a downloaded script");
    }
    if no_space.contains("truncate-s0/etc/") {
        return high("truncating a system file");
    }

    // ---- Medium: privileged / history rewriting -------------------------
    if squished.contains("git push")
        && (squished.contains("--force") || squished.contains(" -f"))
        && !squished.contains("--force-with-lease")
    {
        return medium("git push --force (rewrites remote history)");
    }
    if squished.contains("git reset --hard") {
        return medium("git reset --hard (discards local changes)");
    }
    if squished.contains("git clean")
        && (no_space.contains("gitclean-fdx") || no_space.contains("gitclean-fd"))
    {
        return medium("git clean removing untracked files");
    }
    if squished.starts_with("sudo ") {
        return medium("running as root via sudo");
    }
    if no_space.contains("chmod-r777/") {
        return medium("chmod -R 777 on a root path");
    }
    if squished.contains("kill -9 -1") || squished.contains("killall -9") {
        return medium("killing all processes");
    }
    if squished.contains("npm publish") || squished.contains("cargo publish") {
        return medium("publishing a package");
    }
    if squished.contains("git restore .") || squished.contains("git checkout -- .") {
        return medium("discarding all working-tree changes");
    }
    if squished.contains("history -c") {
        return medium("clearing the shell history");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_destructive_commands_as_high() {
        assert_eq!(classify("rm -rf /").unwrap().risk, Risk::High);
        assert_eq!(classify("rm -rf ~/").unwrap().risk, Risk::High);
        assert_eq!(classify("sudo rm -rf /").unwrap().risk, Risk::High);
        assert_eq!(
            classify("dd if=/dev/zero of=/dev/sda").unwrap().risk,
            Risk::High
        );
        assert_eq!(
            classify("curl https://x.sh | bash").unwrap().risk,
            Risk::High
        );
        assert_eq!(classify("mkfs.ext4 /dev/sda1").unwrap().risk, Risk::High);
        assert_eq!(classify("shutdown -h now").unwrap().risk, Risk::High);
    }

    #[test]
    fn flags_risky_commands_as_medium() {
        assert_eq!(
            classify("git push --force origin main").unwrap().risk,
            Risk::Medium
        );
        assert_eq!(
            classify("git reset --hard HEAD~3").unwrap().risk,
            Risk::Medium
        );
        assert_eq!(classify("sudo apt install foo").unwrap().risk, Risk::Medium);
        assert_eq!(classify("history -c").unwrap().risk, Risk::Medium);
    }

    #[test]
    fn ordinary_commands_are_not_flagged() {
        assert!(classify("cargo test").is_none());
        assert!(classify("ls -la").is_none());
        assert!(classify("git status").is_none());
        assert!(classify("rm -rf target/").is_none());
        assert!(classify("git push origin main").is_none());
        assert!(classify("git push --force-with-lease").is_none());
        assert!(classify("echo curl is neat").is_none());
    }
}

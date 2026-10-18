//! Permission resolution for agentic tool calls.
//!
//! Pure, local policy logic: given the configured [`Permissions`] and a tool
//! call, decide whether it may run without asking (`allow`), must be confirmed
//! (`ask`) or is refused (`deny`). The human is always the final gate whenever
//! the result is `ask`.

use std::path::Path;

use crate::config::{Action, Permissions};
use crate::core::message::ToolCall;

/// Fallback action for a tool when no rule is configured.
pub fn default_for_tool(tool: &str) -> Action {
    match tool {
        "read_file" | "list_dir" | "glob" | "grep" => Action::Allow,
        _ => Action::Ask,
    }
}

/// Rank for "most restrictive wins" comparisons.
fn rank(action: Action) -> u8 {
    match action {
        Action::Allow => 0,
        Action::Ask => 1,
        Action::Deny => 2,
    }
}

/// The stricter (more restrictive) of two actions.
pub fn combine(a: Action, b: Action) -> Action {
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

fn field(perms: &Permissions, tool: &str) -> Option<Action> {
    match tool {
        "read_file" => perms.read,
        "write_file" => perms.write,
        "edit_file" => perms.edit,
        "list_dir" => perms.list,
        "glob" => perms.glob,
        "grep" => perms.grep,
        "run_shell" => perms.bash,
        "delegate" => perms.delegate,
        _ => None,
    }
}

fn command_of(call: &ToolCall) -> String {
    serde_json::from_str::<serde_json::Value>(&call.arguments)
        .ok()
        .and_then(|v| v["command"].as_str().map(str::to_string))
        .unwrap_or_default()
}

fn path_of(call: &ToolCall) -> String {
    serde_json::from_str::<serde_json::Value>(&call.arguments)
        .ok()
        .and_then(|v| v["path"].as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Best (longest, then strictest) matching command rule for `cmd`.
fn best_bash_match(perms: &Permissions, cmd: &str) -> Option<Action> {
    let mut best: Option<(usize, Action)> = None;
    for (pattern, action) in &perms.bash_rules {
        if wildcard_match(pattern, cmd) {
            let len = pattern.chars().count();
            best = match best {
                None => Some((len, *action)),
                Some((blen, _)) if len > blen => Some((len, *action)),
                Some((blen, baction)) if len == blen => Some((blen, combine(baction, *action))),
                other => other,
            };
        }
    }
    best.map(|(_, a)| a)
}

fn bash_action(perms: &Permissions, cmd: &str) -> Action {
    if let Some(action) = best_bash_match(perms, cmd) {
        return action;
    }
    perms.bash.or(perms.default).unwrap_or(Action::Ask)
}

/// Resolve the action for one call. `external` means the call references a path
/// outside the workspace.
pub fn resolve(perms: &Permissions, call: &ToolCall, external: bool) -> Action {
    let base = if call.name == "run_shell" {
        bash_action(perms, &command_of(call))
    } else {
        field(perms, &call.name)
            .or(perms.default)
            .unwrap_or_else(|| default_for_tool(&call.name))
    };
    if external {
        let ext = perms
            .external_directory
            .or(perms.default)
            .unwrap_or(Action::Ask);
        combine(base, ext)
    } else {
        base
    }
}

/// True when the call references a path outside `workspace` (or uses `..`).
pub fn call_is_external(call: &ToolCall, workspace: &Path) -> bool {
    match call.name.as_str() {
        "read_file" | "write_file" | "edit_file" | "list_dir" | "glob" | "grep" => {}
        _ => return false,
    }
    let raw = path_of(call);
    if raw.is_empty() {
        return false;
    }
    crate::core::builtin_tools::resolve_in_workspace(workspace, &raw).is_err()
}

/// Glob-style match supporting `*` (any sequence, including `/`) and `?`.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(name: &str, args: serde_json::Value) -> ToolCall {
        ToolCall {
            id: "1".into(),
            name: name.into(),
            arguments: args.to_string(),
        }
    }

    #[test]
    fn wildcard_matches_expected_shapes() {
        assert!(wildcard_match("git status*", "git status --short"));
        assert!(wildcard_match("*.rs", "src/main.rs"));
        assert!(wildcard_match("**/*.rs", "src/core/engine.rs"));
        assert!(wildcard_match("rm *", "rm -rf /"));
        assert!(!wildcard_match("git status*", "git push"));
        assert!(wildcard_match("a?c", "abc"));
        assert!(!wildcard_match("a?c", "ac"));
    }

    #[test]
    fn defaults_are_read_only_friendly() {
        let perms = Permissions::default();
        assert_eq!(
            resolve(
                &perms,
                &call("read_file", serde_json::json!({"path": "a.txt"})),
                false
            ),
            Action::Allow
        );
        assert_eq!(
            resolve(
                &perms,
                &call("glob", serde_json::json!({"pattern": "*.rs"})),
                false
            ),
            Action::Allow
        );
        assert_eq!(
            resolve(
                &perms,
                &call("run_shell", serde_json::json!({"command": "ls"})),
                false
            ),
            Action::Ask
        );
        assert_eq!(
            resolve(
                &perms,
                &call("write_file", serde_json::json!({"path": "a"})),
                false
            ),
            Action::Ask
        );
    }

    #[test]
    fn explicit_rule_overrides_default() {
        let perms = Permissions {
            bash: Some(Action::Deny),
            ..Default::default()
        };
        assert_eq!(
            resolve(
                &perms,
                &call("run_shell", serde_json::json!({"command": "ls"})),
                false
            ),
            Action::Deny
        );
    }

    #[test]
    fn bash_rules_pick_longest_then_strictest() {
        let mut perms = Permissions::default();
        perms.bash_rules.insert("git *".into(), Action::Allow);
        perms.bash_rules.insert("git push*".into(), Action::Deny);
        assert_eq!(
            resolve(
                &perms,
                &call("run_shell", serde_json::json!({"command": "git status"})),
                false
            ),
            Action::Allow
        );
        assert_eq!(
            resolve(
                &perms,
                &call(
                    "run_shell",
                    serde_json::json!({"command": "git push origin"})
                ),
                false
            ),
            Action::Deny
        );
    }

    #[test]
    fn external_directory_is_stricter() {
        let perms = Permissions::default();
        let c = call("read_file", serde_json::json!({"path": "../secret.txt"}));
        let ws = Path::new("/tmp/ws");
        assert!(call_is_external(&c, ws));
        assert_eq!(resolve(&perms, &c, true), Action::Ask);
    }
}

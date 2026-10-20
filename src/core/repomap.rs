//! A compact, local map of the repository: which files define which symbols.
//!
//! Fully offline and dependency-free: files are walked locally (skipping
//! build/VCS noise) and top-level symbols are extracted with language-specific
//! regular expressions. The map is bounded in size so it can be injected into
//! the context (or returned by the `repo_map` tool) without blowing the budget.

use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;

/// Source extensions we know how to summarise.
const SOURCE_EXT: &[&str] = &[
    "rs", "py", "js", "jsx", "mjs", "cjs", "ts", "tsx", "go", "java", "kt", "kts", "rb", "php",
    "swift", "c", "h", "cc", "cpp", "hpp", "cs", "sh", "bash", "zsh",
];

/// Maximum symbols reported per file.
const MAX_SYMBOLS_PER_FILE: usize = 40;

fn re_rust() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:fn|struct|enum|trait|mod|const|static|type|macro_rules!)\s+([A-Za-z_][A-Za-z0-9_]*)",
        )
        .expect("valid regex")
    })
}

fn re_python() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?m)^\s*(?:async\s+)?(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)")
            .expect("valid regex")
    })
}

fn re_js() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?m)^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function|class|const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)",
        )
        .expect("valid regex")
    })
}

fn re_go() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?m)^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)")
            .expect("valid regex")
    })
}

fn re_names() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?m)^\s*(?:public\s+|private\s+|protected\s+|static\s+|final\s+|internal\s+|open\s+|abstract\s+|def\s+|func\s+|class\s+|interface\s+|enum\s+|struct\s+|record\s+|module\s+|type\s+)*([A-Z][A-Za-z0-9_]*)\s*[({<:]")
            .expect("valid regex")
    })
}

/// Extract the top-level symbol names from a source file.
pub fn symbols_for(path: &Path, content: &str) -> Vec<String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let re = match ext.as_str() {
        "rs" => re_rust(),
        "py" => re_python(),
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" => re_js(),
        "go" => re_go(),
        _ => re_names(),
    };
    let mut out: Vec<String> = Vec::new();
    for cap in re.captures_iter(content) {
        if let Some(m) = cap.get(1) {
            let name = m.as_str().to_string();
            if !out.contains(&name) {
                out.push(name);
            }
        }
        if out.len() >= MAX_SYMBOLS_PER_FILE {
            break;
        }
    }
    out
}

/// The rendered repository map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepoMap {
    pub text: String,
    pub files: usize,
    pub truncated: bool,
}

impl RepoMap {
    pub fn is_empty(&self) -> bool {
        self.text.trim().is_empty()
    }
}

/// Build a bounded repository map rooted at `workspace`.
///
/// Files are ranked by symbol count (busiest first), then path. The output is
/// capped at `max_files` entries and `max_chars` characters.
pub fn build(workspace: &Path, max_files: usize, max_chars: usize) -> RepoMap {
    let mut entries: Vec<(usize, String, Vec<String>)> = Vec::new();

    for path in crate::core::builtin_tools::list_files(workspace) {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !SOURCE_EXT.contains(&ext.as_str()) {
            continue;
        }
        let rel = path
            .strip_prefix(workspace)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let syms = symbols_for(&path, &content);
        if syms.is_empty() {
            continue;
        }
        let score = syms.len();
        entries.push((score, rel, syms));
    }

    entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

    let total = entries.len();
    let mut text = String::new();
    let mut files = 0usize;
    let mut truncated = false;
    for (_, path, syms) in entries.iter() {
        let line = format!("{path}: {}\n", syms.join(", "));
        if files >= max_files || text.len() + line.len() > max_chars {
            truncated = true;
            break;
        }
        text.push_str(&line);
        files += 1;
    }
    if truncated {
        let more = total.saturating_sub(files);
        text.push_str(&format!("… ({more} more file(s) not shown)\n"));
    }
    RepoMap {
        text: text.trim_end().to_string(),
        files,
        truncated,
    }
}

/// Filter a map's lines by a case-insensitive path/symbol substring.
pub fn filter(map: &RepoMap, needle: &str) -> RepoMap {
    let needle = needle.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return map.clone();
    }
    let lines: Vec<&str> = map
        .text
        .lines()
        .filter(|l| l.to_ascii_lowercase().contains(&needle))
        .collect();
    RepoMap {
        text: lines.join("\n"),
        files: lines.len(),
        truncated: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_rust_symbols() {
        let src = "pub fn alpha() {}\nstruct Beta;\nimpl Beta {}\npub mod gamma;\n";
        let syms = symbols_for(Path::new("x.rs"), src);
        assert!(syms.contains(&"alpha".to_string()));
        assert!(syms.contains(&"Beta".to_string()));
        assert!(syms.contains(&"gamma".to_string()));
    }

    #[test]
    fn extracts_python_and_js_symbols() {
        let py = symbols_for(
            Path::new("a.py"),
            "class Foo:\n    pass\n\ndef bar():\n    pass\n",
        );
        assert_eq!(py, vec!["Foo", "bar"]);
        let js = symbols_for(
            Path::new("a.js"),
            "export function baz() {}\nconst qux = 1;\n",
        );
        assert!(js.contains(&"baz".to_string()));
        assert!(js.contains(&"qux".to_string()));
    }

    #[test]
    fn build_summarises_a_workspace_and_is_bounded() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path();
        std::fs::create_dir_all(ws.join("src")).unwrap();
        std::fs::write(ws.join("src/lib.rs"), "pub fn one() {}\npub fn two() {}\n").unwrap();
        std::fs::write(ws.join("src/app.py"), "def three():\n    pass\n").unwrap();
        std::fs::write(ws.join("README.md"), "# not source\n").unwrap();

        let map = build(ws, 50, 10_000);
        assert!(map.text.contains("src/lib.rs: one, two"));
        assert!(map.text.contains("src/app.py: three"));
        assert!(!map.text.contains("README.md"));
        assert_eq!(map.files, 2);

        let tiny = build(ws, 50, 30);
        assert!(tiny.truncated);
        let filtered = filter(&map, "lib.rs");
        assert_eq!(filtered.files, 1);
    }
}

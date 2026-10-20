//! Agent Skills: local, on-demand instruction packs.
//!
//! A skill is a `SKILL.md` file (optional `---` front-matter with `name` and
//! `description`, then a Markdown body). Skills are discovered from the
//! project (`<workspace>/.enclave/skills/<name>/SKILL.md`) and from the global
//! config directory (`<config>/skills/<name>/SKILL.md`); the project wins on
//! name clashes. Discovery is local only — nothing is fetched remotely.
//!
//! Progressive disclosure: only the name + description is offered to the model
//! (see `ChatEngine::system_parts`), and the full body is loaded on demand by
//! the `skill` tool. This keeps the context small until a skill is actually
//! needed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::Result;

/// Sub-directory (under `.enclave/` or the config dir) holding the skills.
pub const SKILLS_SUBDIR: &str = "skills";
/// The file that defines a skill.
pub const SKILL_FILE: &str = "SKILL.md";

/// One discovered skill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skill {
    pub name: String,
    pub description: String,
    pub body: String,
    pub path: PathBuf,
}

impl Skill {
    /// Expand a skill into the text handed back to the model.
    pub fn expand(&self) -> String {
        format!("# Skill: {}\n\n{}", self.name, self.body.trim_end())
    }
}

/// The project skills directory.
pub fn project_dir(workspace: &Path) -> PathBuf {
    workspace.join(".enclave").join(SKILLS_SUBDIR)
}

/// The global skills directory.
pub fn global_dir(config_dir: &Path) -> PathBuf {
    config_dir.join(SKILLS_SUBDIR)
}

/// Parse a `SKILL.md`: optional `---` front-matter (`name`, `description`)
/// followed by the body.
pub fn parse(raw: &str) -> (String, String) {
    let mut name = String::new();
    let mut description = String::new();
    let mut body = raw;

    let trimmed = raw.strip_prefix('\u{feff}').unwrap_or(raw);
    if let Some(rest) = trimmed.strip_prefix("---") {
        // Front-matter ends at the next line that is exactly `---`.
        if let Some(end) = rest.find("\n---") {
            let front = &rest[..end];
            body = rest[end + 4..].trim_start_matches(['\r', '\n']);
            for line in front.lines() {
                let line = line.trim();
                if let Some(v) = line.strip_prefix("name:") {
                    name = v.trim().trim_matches(['"', '\'']).to_string();
                } else if let Some(v) = line.strip_prefix("description:") {
                    description = v.trim().trim_matches(['"', '\'']).to_string();
                }
            }
        }
    }

    if description.is_empty() {
        description = body
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .unwrap_or("")
            .to_string();
    }
    (name, description)
}

fn read_skill(name: &str, path: &Path) -> Option<Skill> {
    let raw = std::fs::read_to_string(path).ok()?;
    let (fm_name, description) = parse(&raw);
    let name = if fm_name.is_empty() {
        name.to_string()
    } else {
        fm_name
    };
    Some(Skill {
        name,
        description,
        body: raw,
        path: path.to_path_buf(),
    })
}

fn collect(dir: &Path, into: &mut BTreeMap<String, Skill>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let skill_file = path.join(SKILL_FILE);
            if skill_file.is_file() {
                let fallback = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("skill")
                    .to_string();
                if let Some(skill) = read_skill(&fallback, &skill_file) {
                    into.insert(skill.name.clone(), skill);
                }
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("md") {
            let fallback = path
                .file_stem()
                .and_then(|n| n.to_str())
                .unwrap_or("skill")
                .to_string();
            if let Some(skill) = read_skill(&fallback, &path) {
                into.insert(skill.name.clone(), skill);
            }
        }
    }
}

/// Discover all skills (global first, project overrides by name).
pub fn load_all(workspace: &Path, config_dir: &Path) -> Result<Vec<Skill>> {
    let mut map: BTreeMap<String, Skill> = BTreeMap::new();
    collect(&global_dir(config_dir), &mut map);
    collect(&project_dir(workspace), &mut map);
    Ok(map.into_values().collect())
}

/// The registry shared with the tool layer.
#[derive(Debug, Clone, Default)]
pub struct SkillsRegistry {
    skills: Vec<Skill>,
}

impl SkillsRegistry {
    pub fn new(skills: Vec<Skill>) -> Self {
        Self { skills }
    }

    pub fn is_empty(&self) -> bool {
        self.skills.is_empty()
    }

    pub fn len(&self) -> usize {
        self.skills.len()
    }

    /// (name, description) pairs, for UIs.
    pub fn entries(&self) -> Vec<(String, String)> {
        self.skills
            .iter()
            .map(|s| (s.name.clone(), s.description.clone()))
            .collect()
    }

    pub fn names(&self) -> Vec<String> {
        self.skills.iter().map(|s| s.name.clone()).collect()
    }

    pub fn get(&self, name: &str) -> Option<&Skill> {
        let needle = name.trim().to_ascii_lowercase();
        self.skills
            .iter()
            .find(|s| s.name.to_ascii_lowercase() == needle)
    }

    /// Compact index (name — description) for the system prompt.
    pub fn index_text(&self) -> String {
        let mut out = String::from(
            "# Skills (local instruction packs — call the `skill` tool with a name to load one)\n",
        );
        for s in &self.skills {
            let desc = s.description.trim();
            out.push_str("- ");
            out.push_str(&s.name);
            if !desc.is_empty() {
                out.push_str(": ");
                out.push_str(desc);
            }
            out.push('\n');
        }
        out.trim_end().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn parses_frontmatter_and_body() {
        let raw = "---\nname: deploy\ndescription: How to deploy\n---\n# Deploy\nrun it\n";
        let (name, desc) = parse(raw);
        assert_eq!(name, "deploy");
        assert_eq!(desc, "How to deploy");
    }

    #[test]
    fn without_frontmatter_uses_first_line_as_description() {
        let (name, desc) = parse("# Notes\n\nSome text\n");
        assert!(name.is_empty());
        assert_eq!(desc, "Some text");
    }

    #[test]
    fn project_overrides_global_and_dirs_are_discovered() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("ws");
        let cfg = tmp.path().join("cfg");
        write(
            &global_dir(&cfg).join("a").join(SKILL_FILE),
            "---\nname: a\ndescription: global A\n---\nglobal body\n",
        );
        write(
            &project_dir(&ws).join("a").join(SKILL_FILE),
            "---\nname: a\ndescription: project A\n---\nproject body\n",
        );
        write(
            &project_dir(&ws).join("b").join(SKILL_FILE),
            "---\nname: b\ndescription: B\n---\nbody b\n",
        );
        let skills = load_all(&ws, &cfg).unwrap();
        assert_eq!(skills.len(), 2);
        let a = skills.iter().find(|s| s.name == "a").unwrap();
        assert_eq!(a.description, "project A");
        let reg = SkillsRegistry::new(skills);
        assert!(reg.get("B").is_some());
        assert!(reg.get("nope").is_none());
        assert!(reg.index_text().contains("- b: B"));
    }
}

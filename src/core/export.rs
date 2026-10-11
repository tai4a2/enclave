//! Conversation export: Markdown, standalone HTML and (best-effort) PDF.
//!
//! Everything runs locally. HTML and Markdown are produced natively; PDF is
//! rendered with an external tool when one is available (`pandoc`, then
//! `wkhtmltopdf`) and reported as unavailable otherwise — nothing is ever sent
//! to a remote service.

use std::path::Path;
use std::process::Command;

use crate::core::message::{Message, Role};
use crate::error::{EnclaveError, Result};

/// Which format to export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Markdown,
    Html,
    Pdf,
}

impl Format {
    pub fn parse(name: &str) -> Option<Format> {
        match name.trim().to_ascii_lowercase().as_str() {
            "md" | "markdown" => Some(Format::Markdown),
            "html" | "htm" => Some(Format::Html),
            "pdf" => Some(Format::Pdf),
            _ => None,
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Format::Markdown => "md",
            Format::Html => "html",
            Format::Pdf => "pdf",
        }
    }
}

/// Render the conversation as Markdown.
pub fn render_markdown(name: &str, model: &str, messages: &[Message]) -> String {
    let mut out = String::new();
    out.push_str(&format!("# {name}\n\n"));
    out.push_str(&format!("_model: {model} · exported by Enclave_\n\n"));
    for m in messages {
        let label = match m.role {
            Role::User => "## You",
            Role::Assistant => "## Assistant",
            Role::Tool => "## Tool",
            Role::System => "## System",
        };
        out.push_str(label);
        out.push_str("\n\n");
        out.push_str(m.content.trim_end());
        out.push_str("\n\n");
    }
    out
}

fn escape_html(text: &str) -> String {
    let mut s = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => s.push_str("&amp;"),
            '<' => s.push_str("&lt;"),
            '>' => s.push_str("&gt;"),
            '"' => s.push_str("&quot;"),
            _ => s.push(c),
        }
    }
    s
}

/// Convert the small Markdown subset Enclave produces into HTML.
fn markdown_to_html(text: &str) -> String {
    let mut html = String::new();
    let mut in_code = false;
    let mut in_list = false;
    let mut paragraph = String::new();

    let flush_paragraph = |html: &mut String, paragraph: &mut String| {
        if !paragraph.trim().is_empty() {
            html.push_str("<p>");
            html.push_str(&inline_html(paragraph.trim()));
            html.push_str("</p>\n");
        }
        paragraph.clear();
    };

    for line in text.lines() {
        let trimmed = line.trim_end();
        if trimmed.trim_start().starts_with("```") {
            if in_code {
                html.push_str("</code></pre>\n");
                in_code = false;
            } else {
                flush_paragraph(&mut html, &mut paragraph);
                html.push_str("<pre><code>");
                in_code = true;
            }
            continue;
        }
        if in_code {
            html.push_str(&escape_html(trimmed));
            html.push('\n');
            continue;
        }
        if trimmed.trim().is_empty() {
            flush_paragraph(&mut html, &mut paragraph);
            if in_list {
                html.push_str("</ul>\n");
                in_list = false;
            }
            continue;
        }
        if let Some(rest) = heading_text(trimmed) {
            flush_paragraph(&mut html, &mut paragraph);
            if in_list {
                html.push_str("</ul>\n");
                in_list = false;
            }
            let (level, text) = rest;
            html.push_str(&format!("<h{level}>{}</h{level}>\n", inline_html(text)));
            continue;
        }
        if let Some(item) = trimmed.trim_start().strip_prefix("- ") {
            flush_paragraph(&mut html, &mut paragraph);
            if !in_list {
                html.push_str("<ul>\n");
                in_list = true;
            }
            html.push_str(&format!("<li>{}</li>\n", inline_html(item)));
            continue;
        }
        if !paragraph.is_empty() {
            paragraph.push('\n');
        }
        paragraph.push_str(trimmed.trim_start());
    }
    flush_paragraph(&mut html, &mut paragraph);
    if in_list {
        html.push_str("</ul>\n");
    }
    if in_code {
        html.push_str("</code></pre>\n");
    }
    html
}

fn heading_text(line: &str) -> Option<(usize, &str)> {
    let hashes = line.chars().take_while(|c| *c == '#').count();
    if (1..=3).contains(&hashes) && line.chars().nth(hashes) == Some(' ') {
        Some((hashes, line[hashes + 1..].trim()))
    } else {
        None
    }
}

/// Inline Markdown: `code`, **bold**, *italic*, escaped HTML.
fn inline_html(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '`' => {
                let mut buf = String::new();
                for c in chars.by_ref() {
                    if c == '`' {
                        break;
                    }
                    buf.push(c);
                }
                out.push_str(&format!("<code>{}</code>", escape_html(&buf)));
            }
            '*' => {
                let bold = chars.peek() == Some(&'*');
                if bold {
                    chars.next();
                }
                let mut buf = String::new();
                let mut closed = false;
                while let Some(c) = chars.next() {
                    if c == '*' {
                        if bold {
                            if chars.peek() == Some(&'*') {
                                chars.next();
                                closed = true;
                                break;
                            }
                            buf.push(c);
                        } else {
                            closed = true;
                            break;
                        }
                    } else {
                        buf.push(c);
                    }
                }
                if closed {
                    let tag = if bold { "strong" } else { "em" };
                    out.push_str(&format!("<{tag}>{}</{tag}>", escape_html(&buf)));
                } else {
                    out.push('*');
                    if bold {
                        out.push('*');
                    }
                    out.push_str(&escape_html(&buf));
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Render a standalone, styled HTML document.
pub fn render_html(name: &str, model: &str, messages: &[Message]) -> String {
    let mut body = String::new();
    for m in messages {
        let (class, label) = match m.role {
            Role::User => ("user", "You"),
            Role::Assistant => ("assistant", "Assistant"),
            Role::Tool => ("tool", "Tool"),
            Role::System => ("system", "System"),
        };
        body.push_str(&format!(
            "<section class=\"{class}\"><div class=\"role\">{label}</div>{}",
            markdown_to_html(&m.content)
        ));
        if !m.attachments.is_empty() {
            body.push_str("<div class=\"attachments\">");
            for a in &m.attachments {
                body.push_str(&format!("📎 {}", escape_html(&a.name)));
            }
            body.push_str("</div>");
        }
        body.push_str("</section>\n");
    }
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>{title}</title><style>{css}</style></head><body>\
<header><h1>◆ {title}</h1><p class=\"meta\">model: {model} · exported by Enclave</p></header>\
<main>{body}</main></body></html>\n",
        title = escape_html(name),
        model = escape_html(model),
        css = CSS,
        body = body,
    )
}

const CSS: &str = r#"
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#111216;color:#e2e2e8;font:15px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
header{padding:24px 32px;border-bottom:1px solid #2c2e36}
header h1{margin:0;color:#a78bfa;font-size:20px}
.meta{margin:4px 0 0;color:#848694;font-size:13px}
main{max-width:900px;margin:0 auto;padding:24px 32px 80px}
section{padding:14px 18px;border-radius:10px;margin:14px 0}
section.user{background:#2c2e36}
section.assistant{background:#1e1f25}
section.tool{background:#181920;border-left:3px solid #e5c07b}
section.system{background:#141519;border-left:3px solid #565869}
.role{font-size:12px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#848694;margin-bottom:6px}
section.user .role{color:#a78bfa}
pre{background:#0d0e12;border:1px solid #2c2e36;border-radius:8px;padding:12px;overflow:auto}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;color:#e5c07b}
pre code{color:#e2e2e8}
h1,h2,h3{color:#e2e2e8}
a{color:#a78bfa}
.attachments{margin-top:6px;color:#848694;font-size:13px}
.attachments span{margin-right:10px}
"#;

fn tool_available(cmd: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {cmd}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Export the conversation to `out`, creating parent directories.
///
/// Returns the path written. For `Pdf` this requires `pandoc` or
/// `wkhtmltopdf` on the PATH; otherwise an error explains the fallback.
pub fn export(
    name: &str,
    model: &str,
    messages: &[Message],
    format: Format,
    out: &Path,
) -> Result<()> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match format {
        Format::Markdown => {
            std::fs::write(out, render_markdown(name, model, messages))?;
        }
        Format::Html => {
            std::fs::write(out, render_html(name, model, messages))?;
        }
        Format::Pdf => {
            let md = render_markdown(name, model, messages);
            export_pdf(&md, name, model, messages, out)?;
        }
    }
    Ok(())
}

fn export_pdf(
    md: &str,
    name: &str,
    model: &str,
    messages: &[Message],
    out: &Path,
) -> Result<()> {
    let tmp_md = std::env::temp_dir().join(format!("enclave-export-{}.md", std::process::id()));
    std::fs::write(&tmp_md, md)?;

    if tool_available("pandoc") {
        let status = Command::new("pandoc")
            .arg(&tmp_md)
            .arg("-o")
            .arg(out)
            .status()
            .map_err(|e| EnclaveError::other(format!("pandoc failed to start: {e}")))?;
        if status.success() {
            let _ = std::fs::remove_file(&tmp_md);
            return Ok(());
        }
        return Err(EnclaveError::other("pandoc could not produce the PDF"));
    }

    if tool_available("wkhtmltopdf") {
        let tmp_html = std::env::temp_dir().join(format!("enclave-export-{}.html", std::process::id()));
        std::fs::write(&tmp_html, render_html(name, model, messages))?;
        let status = Command::new("wkhtmltopdf")
            .arg(&tmp_html)
            .arg(out)
            .status()
            .map_err(|e| EnclaveError::other(format!("wkhtmltopdf failed to start: {e}")))?;
        let _ = std::fs::remove_file(&tmp_md);
        let _ = std::fs::remove_file(&tmp_html);
        if status.success() {
            return Ok(());
        }
        return Err(EnclaveError::other("wkhtmltopdf could not produce the PDF"));
    }

    let _ = std::fs::remove_file(&tmp_md);
    Err(EnclaveError::other(
        "PDF export needs `pandoc` or `wkhtmltopdf` installed — \
         use `/export html` for a self-contained page instead",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msgs() -> Vec<Message> {
        vec![
            Message::user("hello **world**"),
            Message::assistant("```rust\nfn main() {}\n```\n\nsee `code`"),
        ]
    }

    #[test]
    fn markdown_has_headers_and_roles() {
        let md = render_markdown("chat", "gpt-4o", &msgs());
        assert!(md.contains("# chat"));
        assert!(md.contains("## You"));
        assert!(md.contains("## Assistant"));
    }

    #[test]
    fn html_escapes_and_renders_code() {
        let html = render_html("chat</title>", "m", &msgs());
        assert!(html.contains("&lt;/title&gt;"));
        assert!(html.contains("<pre><code>"));
        assert!(html.contains("<strong>world</strong>"));
        assert!(html.contains("<code>code</code>"));
    }

    #[test]
    fn format_parsing() {
        assert_eq!(Format::parse("MD"), Some(Format::Markdown));
        assert_eq!(Format::parse("html"), Some(Format::Html));
        assert_eq!(Format::parse("pdf"), Some(Format::Pdf));
        assert_eq!(Format::parse("docx"), None);
    }
}

//! Conversation export: Markdown, standalone HTML and PDF.
//!
//! Everything runs locally and natively. Markdown and HTML are produced as
//! strings; PDF is rendered by a small built-in generator (no `pandoc` or
//! `wkhtmltopdf` required) — nothing is ever sent to a remote service.

use std::path::Path;

use crate::core::message::{Message, Role};
use crate::error::Result;

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

/// Export the conversation to `out`, creating parent directories.
///
/// Returns the path written. PDF is rendered natively (no external tools).
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
            std::fs::write(out, render_pdf(name, model, messages))?;
        }
    }
    Ok(())
}

// --------------------------------------------------------------------------
// Native PDF renderer (no external dependencies).
//
// Produces a PDF 1.4 document using the built-in Helvetica / Helvetica-Bold
// fonts, with simple word-wrapping and pagination. Text is transliterated to
// Windows-1252 so any Unicode the terminal produced still renders.
// --------------------------------------------------------------------------

/// One laid-out line of the document.
struct PdfLine {
    text: String,
    bold: bool,
    size: f32,
}

/// Map a Unicode string to something the base-14 fonts (WinAnsi) can show,
/// replacing common punctuation with ASCII and dropping the rest to '?'.
fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\t' => out.push_str("    "),
            '·' | '•' => out.push('*'),
            '—' | '–' => out.push('-'),
            '“' | '”' => out.push('"'),
            '‘' | '’' => out.push('\''),
            '…' => out.push_str("..."),
            '→' => out.push_str("->"),
            '◆' => out.push('*'),
            '\u{00a0}' => out.push(' '),
            c if (c as u32) < 32 && c != '\n' => {}
            c if (c as u32) <= 0xFF => out.push(c),
            _ => out.push('?'),
        }
    }
    out
}

/// Escape a string for a PDF literal string object.
fn pdf_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) > 0x7F => {
                // Encode as a Windows-1252 byte via an octal escape.
                let b = c as u32 as u8;
                out.push_str(&format!("\\{:03o}", b));
            }
            _ => out.push(c),
        }
    }
    out
}

/// Greedy word-wrap `text` to at most `max_cols` characters, preserving the
/// explicit line breaks in the source.
fn wrap_text(text: &str, max_cols: usize) -> Vec<String> {
    let max_cols = max_cols.max(8);
    let mut lines = Vec::new();
    for raw in text.split('\n') {
        let raw = raw.trim_end();
        if raw.is_empty() {
            lines.push(String::new());
            continue;
        }
        let mut cur = String::new();
        for word in raw.split(' ') {
            let wlen = word.chars().count();
            let curlen = cur.chars().count();
            if curlen == 0 {
                if wlen > max_cols {
                    // Hard-split a word longer than the column budget.
                    let mut buf = String::new();
                    for ch in word.chars() {
                        buf.push(ch);
                        if buf.chars().count() >= max_cols {
                            lines.push(std::mem::take(&mut buf));
                        }
                    }
                    cur = buf;
                } else {
                    cur.push_str(word);
                }
            } else if curlen + 1 + wlen <= max_cols {
                cur.push(' ');
                cur.push_str(word);
            } else {
                lines.push(std::mem::take(&mut cur));
                cur.push_str(word);
            }
        }
        if !cur.is_empty() {
            lines.push(cur);
        }
    }
    lines
}

fn text_cols(size: f32) -> usize {
    // Usable width ~ 483pt (A4 minus margins); Helvetica averages ~0.5em/char.
    (483.0 / (size * 0.52)).floor().max(8.0) as usize
}

/// Flatten the conversation into styled, wrapped lines.
fn layout(name: &str, model: &str, messages: &[Message]) -> Vec<PdfLine> {
    let mut out = Vec::new();
    let mut push = |text: String, bold: bool, size: f32| out.push(PdfLine { text, bold, size });

    for l in wrap_text(&sanitize(name), text_cols(18.0)) {
        push(l, true, 18.0);
    }
    for l in wrap_text(
        &sanitize(&format!("model: {model} - exported by Enclave")),
        text_cols(10.0),
    ) {
        push(l, false, 10.0);
    }
    push(String::new(), false, 10.0);

    for m in messages {
        let label = match m.role {
            Role::User => "You",
            Role::Assistant => "Assistant",
            Role::Tool => "Tool",
            Role::System => "System",
        };
        push(label.to_string(), true, 12.0);
        for l in wrap_text(&sanitize(m.content.trim_end()), text_cols(11.0)) {
            push(l, false, 11.0);
        }
        if !m.attachments.is_empty() {
            let names = m
                .attachments
                .iter()
                .map(|a| a.name.clone())
                .collect::<Vec<_>>()
                .join(", ");
            for l in wrap_text(&format!("[attachments: {names}]"), text_cols(10.0)) {
                push(l, false, 10.0);
            }
        }
        push(String::new(), false, 10.0);
    }
    out
}

/// Render the whole conversation as PDF bytes.
pub fn render_pdf(name: &str, model: &str, messages: &[Message]) -> Vec<u8> {
    const PAGE_W: f32 = 595.0;
    const PAGE_H: f32 = 842.0;
    const MARGIN: f32 = 56.0;
    const BOTTOM: f32 = 60.0;

    let lines = layout(name, model, messages);

    // Paginate into per-page content streams.
    let mut pages: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut y = PAGE_H - MARGIN;
    cur.push_str("BT\n");
    for line in &lines {
        let lh = line.size * 1.35;
        if y - lh < BOTTOM {
            cur.push_str("ET\n");
            pages.push(std::mem::take(&mut cur));
            cur.push_str("BT\n");
            y = PAGE_H - MARGIN;
        }
        y -= lh;
        let font = if line.bold { "F2" } else { "F1" };
        cur.push_str(&format!(
            "1 0 0 1 {MARGIN:.1} {y:.1} Tm\n/{font} {:.1} Tf\n({}) Tj\n",
            line.size,
            pdf_escape(&line.text)
        ));
    }
    cur.push_str("ET\n");
    pages.push(cur);
    if pages.is_empty() {
        pages.push("BT\nET\n".to_string());
    }

    // Assemble the file.
    let n = pages.len();
    let first_page_obj = 3;
    let f1_obj = first_page_obj + n * 2;
    let f2_obj = f1_obj + 1;

    let mut objects: Vec<(usize, String)> = Vec::new();
    objects.push((1, "<< /Type /Catalog /Pages 2 0 R >>".to_string()));
    let kids: Vec<String> = (0..n)
        .map(|p| format!("{} 0 R", first_page_obj + p * 2))
        .collect();
    objects.push((
        2,
        format!("<< /Type /Pages /Kids [{}] /Count {n} >>", kids.join(" ")),
    ));
    for (p, content) in pages.iter().enumerate() {
        let page_obj = first_page_obj + p * 2;
        let content_obj = page_obj + 1;
        objects.push((
            page_obj,
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W:.0} {PAGE_H:.0}] \
                 /Resources << /Font << /F1 {f1_obj} 0 R /F2 {f2_obj} 0 R >> >> \
                 /Contents {content_obj} 0 R >>"
            ),
        ));
        objects.push((
            content_obj,
            format!(
                "<< /Length {} >>\nstream\n{content}endstream",
                content.len()
            ),
        ));
    }
    objects.push((
        f1_obj,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
            .to_string(),
    ));
    objects.push((
        f2_obj,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
            .to_string(),
    ));

    let mut file = String::new();
    file.push_str("%PDF-1.4\n%\u{00e2}\u{00e3}\u{00cf}\u{00d3}\n");
    let mut offsets = vec![0usize; objects.len() + 1];
    for (id, body) in &objects {
        offsets[*id] = file.len();
        file.push_str(&format!("{id} 0 obj\n{body}\nendobj\n"));
    }
    let xref_pos = file.len();
    let total_objs = f2_obj + 1;
    file.push_str(&format!("xref\n0 {total_objs}\n"));
    file.push_str("0000000000 65535 f \n");
    for id in 1..total_objs {
        let off = offsets.get(id).copied().unwrap_or(0);
        file.push_str(&format!("{off:010} 00000 n \n"));
    }
    file.push_str(&format!(
        "trailer\n<< /Size {total_objs} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n"
    ));

    file.into_bytes()
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

    #[test]
    fn pdf_is_a_wellformed_document() {
        let bytes = render_pdf("chat", "gpt-4o", &msgs());
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("%PDF-1.4"));
        assert!(text.contains("/Type /Catalog"));
        assert!(text.contains("/BaseFont /Helvetica-Bold"));
        assert!(text.trim_end().ends_with("%%EOF"));
    }

    #[test]
    fn pdf_escapes_parentheses_and_wraps() {
        let long = "word ".repeat(2000);
        let bytes = render_pdf(
            "t",
            "m",
            &[Message::user("a (b) c \\ d"), Message::assistant(long)],
        );
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("\\("));
        assert!(text.contains("/Count "));
        // Long content must paginate into more than one page.
        assert!(!text.contains("/Count 1 "));
    }
}

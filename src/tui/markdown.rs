//! Minimal markdown-to-ratatui renderer for assistant messages.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

fn code_style() -> Style {
    Style::default().fg(Color::Yellow)
}

fn heading_style(level: usize) -> Style {
    match level {
        1 => Style::default()
            .fg(Color::LightBlue)
            .add_modifier(Modifier::BOLD),
        _ => Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
    }
}

fn quote_style() -> Style {
    Style::default()
        .fg(Color::Gray)
        .add_modifier(Modifier::ITALIC)
}

/// Render a markdown string as styled transcript lines.
///
/// Supported: fenced code blocks, headings, bullet/numbered lists,
/// blockquotes, inline `code`, **bold**, *italic*. Unrecognized syntax
/// degrades to plain text.
pub fn render(text: &str) -> Vec<Line<'static>> {
    let mut out: Vec<Line> = Vec::new();
    let mut in_code = false;

    for raw in text.lines() {
        let trimmed_start = raw.trim_start();

        // Fenced code blocks: render the body with a dim gutter, hide the fences.
        if trimmed_start.starts_with("```") {
            in_code = !in_code;
            continue;
        }
        if in_code {
            out.push(Line::from(vec![
                Span::styled("│ ", Style::default().fg(Color::DarkGray)),
                Span::styled(raw.to_string(), Style::default().fg(Color::Cyan)),
            ]));
            continue;
        }

        // Headings.
        if let Some(level) = heading_level(trimmed_start) {
            let content = trimmed_start.trim_start_matches('#').trim();
            out.push(Line::from(Span::styled(
                content.to_string(),
                heading_style(level),
            )));
            continue;
        }

        // Blockquotes.
        if trimmed_start.starts_with('>') {
            let content = trimmed_start.trim_start_matches('>').trim();
            out.push(Line::from(Span::styled(
                format!("▌ {content}"),
                quote_style(),
            )));
            continue;
        }

        // Everything else: bullet/list decoration + inline spans.
        let (prefix, rest) = list_prefix(trimmed_start);
        let mut spans: Vec<Span> = Vec::new();
        if let Some(p) = prefix {
            spans.push(Span::styled(p.to_string(), Style::default().fg(Color::Cyan)));
        }
        spans.extend(inline(rest));
        out.push(Line::from(spans));
    }
    out
}

fn heading_level(line: &str) -> Option<usize> {
    let hashes = line.chars().take_while(|c| *c == '#').count();
    if (1..=3).contains(&hashes) && line.chars().nth(hashes) == Some(' ') {
        Some(hashes)
    } else {
        None
    }
}

/// Detect `- ` / `* ` / `1. ` list markers; returns (marker, rest).
fn list_prefix(line: &str) -> (Option<&str>, &str) {
    for m in ["- ", "* ", "+ "] {
        if let Some(rest) = line.strip_prefix(m) {
            return (Some("• "), rest);
        }
    }
    if !line.is_empty() && line.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        if let Some(dot) = line.find(". ") {
            if line[..dot].chars().all(|c| c.is_ascii_digit()) {
                return (Some("  "), &line[dot + 2..]);
            }
        }
    }
    (None, line)
}

/// Split a plain line into spans handling `code`, **bold**, *italic*.
/// Unterminated markers degrade to plain text.
fn inline(text: &str) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let mut plain = String::new();
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '`' {
            // Inline code: scan up to the closing backtick.
            let mut content = String::new();
            let mut closed = false;
            for c2 in chars.by_ref() {
                if c2 == '`' {
                    closed = true;
                    break;
                }
                content.push(c2);
            }
            if closed {
                if !plain.is_empty() {
                    spans.push(Span::raw(std::mem::take(&mut plain)));
                }
                spans.push(Span::styled(content, code_style()));
            } else {
                plain.push('`');
                plain.push_str(&content);
            }
        } else if c == '*' {
            // **bold** (two stars) or *italic* (one star).
            let stars = if chars.peek() == Some(&'*') {
                chars.next();
                2
            } else {
                1
            };
            let mut content = String::new();
            let mut closed = false;
            while let Some(c2) = chars.next() {
                if c2 == '*' {
                    if stars == 2 && chars.peek() == Some(&'*') {
                        chars.next();
                    }
                    closed = true;
                    break;
                }
                content.push(c2);
            }
            if closed {
                if !plain.is_empty() {
                    spans.push(Span::raw(std::mem::take(&mut plain)));
                }
                let style = if stars == 2 {
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default().add_modifier(Modifier::ITALIC)
                };
                spans.push(Span::styled(content, style));
            } else {
                plain.push_str(&"*".repeat(stars));
                plain.push_str(&content);
            }
        } else {
            plain.push(c);
        }
    }
    if !plain.is_empty() {
        spans.push(Span::raw(plain));
    }
    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_of(line: &Line) -> String {
        line.spans.iter().map(|s| s.content.clone()).collect()
    }

    #[test]
    fn headings_are_styled_and_stripped() {
        let l = render("## Title");
        assert_eq!(l.len(), 1);
        assert_eq!(text_of(&l[0]), "Title");
        assert!(l[0].spans[0].style.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn code_blocks_get_gutter_and_are_hidden_fences() {
        let l = render("```bash\necho hi\n```");
        assert_eq!(l.len(), 1);
        assert_eq!(text_of(&l[0]), "│ echo hi");
    }

    #[test]
    fn bullets_and_quotes() {
        let l = render("- item one\n> quoted");
        assert_eq!(l.len(), 2);
        assert_eq!(text_of(&l[0]), "• item one");
        assert_eq!(text_of(&l[1]), "▌ quoted");
    }

    #[test]
    fn numbered_lists() {
        let l = render("1. first\n2. second");
        assert_eq!(text_of(&l[0]), "  first");
        assert_eq!(text_of(&l[1]), "  second");
    }

    #[test]
    fn inline_code_bold_italic() {
        let l = render("use `cargo test` and **bold** and *ital*");
        let spans = &l[0].spans;
        assert!(spans.iter().any(|s| s.content == "cargo test"
            && s.style.fg == Some(Color::Yellow)));
        assert!(spans
            .iter()
            .any(|s| s.content == "bold" && s.style.add_modifier.contains(Modifier::BOLD)));
        assert!(spans
            .iter()
            .any(|s| s.content == "ital" && s.style.add_modifier.contains(Modifier::ITALIC)));
        assert_eq!(text_of(&l[0]), "use cargo test and bold and ital");
    }

    #[test]
    fn unterminated_markers_degrade_to_plain_text() {
        let l = render("a `b and **c");
        assert_eq!(text_of(&l[0]), "a `b and **c");
    }
}
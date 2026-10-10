//! Full-screen terminal UI built on ratatui (opencode-style layout).

use std::io::{Stdout, stdout};
use std::time::Duration;

use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use futures::StreamExt;
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Position};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, List, ListItem, ListState, Paragraph, Wrap,
};

use crate::config::ToolsSettings;
use crate::core::engine::ChatEngine;
use crate::core::message::Role;
use crate::core::tools::{self, Proposal};
use crate::error::Result;
use crate::privacy::SessionInfo;
use crate::providers::ChunkStream;
use crate::tui::markdown;

/// Sidebar width in cells; hidden on narrow terminals.
const SIDEBAR_WIDTH: u16 = 28;
const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Text shown by `/help`.
const SLASH_HELP: &str =
    "commands: /help · /new · /switch · /clear · /model <id> (empty = current) · /quit";

/// One rendered transcript entry.
struct ChatLine {
    speaker: Speaker,
    text: String,
}

#[derive(Clone, Copy, PartialEq)]
enum Speaker {
    User,
    Assistant,
    Tool,
    System,
}

impl Speaker {
    fn label(self) -> &'static str {
        match self {
            Speaker::User => "you",
            Speaker::Assistant => "assistant",
            Speaker::Tool => "tool",
            Speaker::System => "system",
        }
    }

    fn style(self) -> Style {
        match self {
            Speaker::User => Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            Speaker::Assistant => Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            Speaker::Tool => Style::default().fg(Color::Yellow),
            Speaker::System => Style::default().fg(Color::Gray).add_modifier(Modifier::DIM),
        }
    }
}

/// What the app is currently doing.
enum Phase {
    Idle,
    Streaming,
    Confirming {
        proposals: Vec<Proposal>,
        idx: usize,
        approve_all: bool,
    },
    /// Renaming a session: the message input collects the new name.
    Renaming { id: String },
}

/// Which panel has keyboard focus.
#[derive(Clone, Copy, PartialEq)]
enum Focus {
    Chat,
    Sidebar,
}

/// What a key press asks the app to do (input phase).
enum KeyAction {
    None,
    Quit,
    Clear,
    Send,
    ScrollUp,
    ScrollDown,
    DeleteWord,
    ToggleSidebar,
    /// Alt+Enter: start a new line inside the input box.
    Newline,
}

/// What a key press asks the app to do (proposal-confirmation phase).
enum ProposalAction {
    None,
    Quit,
    Approve,
    Deny,
    ApproveAll,
    SkipAll,
}

/// Result of polling the active reply stream.
enum ChunkOutcome {
    Chunk(String),
    Done,
    Error(String),
}

/// Run the interactive TUI until the user quits.
pub async fn run(mut engine: ChatEngine, tools_cfg: ToolsSettings) -> Result<()> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    let result = run_app(&mut engine, tools_cfg, &mut terminal).await;

    let _ = disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    );
    let _ = terminal.show_cursor();

    result
}

async fn run_app(
    engine: &mut ChatEngine,
    tools_cfg: ToolsSettings,
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
) -> Result<()> {
    // Seed the transcript with the persisted history of this session.
    let mut transcript: Vec<ChatLine> = engine
        .session
        .messages
        .iter()
        .map(|m| ChatLine {
            speaker: match m.role {
                Role::User => Speaker::User,
                Role::Assistant => Speaker::Assistant,
                Role::System => Speaker::System,
            },
            text: m.content.clone(),
        })
        .collect();

    let mut sessions = engine.memory.list_sessions().unwrap_or_default();
    let mut sel: usize = 0;
    let mut focus = Focus::Chat;
    let mut input = String::new();
    let mut status = String::from("ready");
    let mut scroll: u16 = 0;
    let mut phase = Phase::Idle;
    let mut spinner_idx: usize = 0;
    let mut active: Option<ChunkStream> = None;
    let mut buffer = String::new();
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(120));

    loop {
        terminal.draw(|f| {
            draw_ui(
                f,
                engine,
                &transcript,
                &input,
                &status,
                scroll,
                &phase,
                focus,
                &sessions,
                sel,
                SPINNER[spinner_idx],
                tools_cfg.enabled,
            )
        })?;

        match phase {
            Phase::Streaming => {
                let mut outcome: Option<ChunkOutcome> = None;
                tokio::select! {
                    _ = tick.tick() => {
                        spinner_idx = (spinner_idx + 1) % SPINNER.len();
                        continue; // redraw with the next spinner frame
                    }
                    maybe = events.next() => {
                        if let Some(Ok(ev)) = maybe {
                            match ev {
                                Event::Key(key) => {
                                    if matches!(handle_key(key, &mut input), KeyAction::Quit) {
                                        return Ok(());
                                    }
                                }
                                Event::Mouse(m) => match m.kind {
                                    MouseEventKind::ScrollUp => scroll = scroll.saturating_add(1),
                                    MouseEventKind::ScrollDown => {
                                        scroll = scroll.saturating_sub(1)
                                    }
                                    _ => {}
                                },
                                _ => {}
                            }
                        }
                    }
                    chunk = active.as_mut().unwrap().next() => {
                        outcome = Some(match chunk {
                            Some(Ok(s)) => ChunkOutcome::Chunk(s),
                            Some(Err(e)) => ChunkOutcome::Error(e.to_string()),
                            None => ChunkOutcome::Done,
                        });
                    }
                }

                match outcome {
                    Some(ChunkOutcome::Chunk(s)) => {
                        buffer.push_str(&s);
                        if let Some(last) = transcript.last_mut() {
                            if last.speaker == Speaker::Assistant {
                                last.text = buffer.clone();
                            }
                        }
                    }
                    Some(ChunkOutcome::Error(e)) => {
                        status = format!("error: {e}");
                        phase = Phase::Idle;
                        active = None;
                    }
                    Some(ChunkOutcome::Done) => {
                        let content = std::mem::take(&mut buffer);
                        match engine.commit_assistant(content) {
                            Ok(()) => status = "ready".into(),
                            Err(e) => status = format!("commit error: {e}"),
                        }
                        active = None;

                        // Offer shell proposals (ask-always, same as the CLI).
                        let proposals = if tools_cfg.enabled {
                            transcript
                                .last()
                                .filter(|l| l.speaker == Speaker::Assistant)
                                .map(|l| tools::extract_proposals(&l.text))
                                .unwrap_or_default()
                        } else {
                            Vec::new()
                        };
                        phase = if proposals.is_empty() {
                            Phase::Idle
                        } else {
                            Phase::Confirming {
                                proposals,
                                idx: 0,
                                approve_all: false,
                            }
                        };
                    }
                    None => {}
                }
            }
            Phase::Confirming { .. } => {
                // Snapshot state to avoid holding borrows while mutating.
                let (proposal, idx, total, approve_all) = match &phase {
                    Phase::Confirming {
                        proposals,
                        idx,
                        approve_all,
                    } => (proposals.get(*idx).cloned(), *idx, proposals.len(), *approve_all),
                    _ => (None, 0, 0, false),
                };

                // "[a]ll" already approved: execute without waiting for keys.
                if approve_all {
                    if let Some(p) = &proposal {
                        execute_proposal(engine, &mut transcript, &mut status, p, tools_cfg.timeout_secs, tools_cfg.max_output_bytes).await?;
                    }
                    advance_proposal(&mut phase, &mut status, idx, total);
                    continue;
                }

                if let Some(Ok(Event::Key(key))) = events.next().await {
                    match handle_proposal_key(key) {
                        ProposalAction::Quit => return Ok(()),
                        ProposalAction::SkipAll => {
                            status = "proposals skipped".into();
                            phase = Phase::Idle;
                        }
                        ProposalAction::Deny => {
                            advance_proposal(&mut phase, &mut status, idx, total);
                        }
                        ProposalAction::ApproveAll => {
                            if let Some(p) = &proposal {
                                execute_proposal(engine, &mut transcript, &mut status, p, tools_cfg.timeout_secs, tools_cfg.max_output_bytes).await?;
                            }
                            if let Phase::Confirming { approve_all, .. } = &mut phase {
                                *approve_all = true;
                            }
                            advance_proposal(&mut phase, &mut status, idx, total);
                        }
                        ProposalAction::Approve => {
                            if let Some(p) = &proposal {
                                execute_proposal(engine, &mut transcript, &mut status, p, tools_cfg.timeout_secs, tools_cfg.max_output_bytes).await?;
                            }
                            advance_proposal(&mut phase, &mut status, idx, total);
                        }
                        ProposalAction::None => {}
                    }
                }
            }
            Phase::Idle => {
                match events.next().await {
                    Some(Ok(Event::Key(key))) => {
                        if focus == Focus::Sidebar {
                            match key.code {
                                KeyCode::Up => sel = sel.saturating_sub(1),
                                KeyCode::Down => {
                                    if !sessions.is_empty() {
                                        sel = (sel + 1).min(sessions.len() - 1);
                                    }
                                }
                                KeyCode::Enter => {
                                    switch_session(
                                        engine,
                                        &sessions,
                                        sel,
                                        &mut transcript,
                                        &mut status,
                                    )?;
                                }
                                KeyCode::Char('n') => {
                                    match crate::core::session::Session::create(
                                        &engine.memory,
                                        "chat",
                                    ) {
                                        Ok(s) => {
                                            engine.session = s;
                                            transcript.clear();
                                            sessions =
                                                engine.memory.list_sessions().unwrap_or_default();
                                            sel = 0;
                                            scroll = 0;
                                            status = "new session created".into();
                                        }
                                        Err(e) => status = format!("error: {e}"),
                                    }
                                }
                                KeyCode::Char('r') => match sessions.get(sel) {
                                    Some(info) => {
                                        phase = Phase::Renaming { id: info.id.clone() };
                                        input.clear();
                                        status = format!(
                                            "renaming '{}' — type name, Enter confirms, Esc cancels",
                                            info.name
                                        );
                                    }
                                    None => status = "no session selected".into(),
                                },
                                KeyCode::Char('d') => match sessions.get(sel).map(|s| (s.id.clone(), s.name.clone())) {
                                    Some((id, _name)) if id == engine.session.id => {
                                        status = "cannot delete the active session — select another first".into();
                                    }
                                    Some((id, name)) => match engine.memory.delete_session(&id) {
                                        Ok(()) => {
                                            sessions =
                                                engine.memory.list_sessions().unwrap_or_default();
                                            sel = sel.min(sessions.len().saturating_sub(1));
                                            status = format!("deleted session '{name}'");
                                        }
                                        Err(e) => status = format!("error: {e}"),
                                    },
                                    None => status = "no session selected".into(),
                                },
                                _ => focus = Focus::Chat,
                            }
                            continue;
                        }

                        let mut send = false;
                        match handle_key(key, &mut input) {
                            KeyAction::Quit => return Ok(()),
                            KeyAction::Clear => match engine.session.clear(&engine.memory) {
                                Ok(()) => {
                                    transcript.clear();
                                    scroll = 0;
                                    status = "session cleared (history wiped)".into();
                                    sessions = engine.memory.list_sessions().unwrap_or_default();
                                }
                                Err(e) => status = format!("error: {e}"),
                            },
                            KeyAction::Send => send = true,
                            KeyAction::ScrollUp => scroll = scroll.saturating_add(1),
                            KeyAction::ScrollDown => scroll = scroll.saturating_sub(1),
                            KeyAction::DeleteWord => delete_word(&mut input),
                            KeyAction::Newline => input.push('\n'),
                            KeyAction::ToggleSidebar => {
                                sessions = engine.memory.list_sessions().unwrap_or_default();
                                focus = Focus::Sidebar;
                                status =
                                    "sessions — ↑/↓ select, Enter open, n new, r rename, d delete, Tab back".into();
                            }
                            KeyAction::None => {}
                        }

                        if send && !input.trim().is_empty() {
                            let text = std::mem::take(&mut input);

                            // Slash commands are local actions, never sent to the provider.
                            if text.starts_with('/') {
                                let mut parts = text.split_whitespace();
                                let cmd = parts.next().unwrap_or("").trim_start_matches('/');
                                let arg = parts.collect::<Vec<_>>().join(" ");
                                match cmd {
                                    "help" => {
                                        transcript.push(ChatLine {
                                            speaker: Speaker::System,
                                            text: SLASH_HELP.into(),
                                        });
                                        status = "ready".into();
                                    }
                                    "new" => {
                                        match crate::core::session::Session::create(
                                            &engine.memory,
                                            "chat",
                                        ) {
                                            Ok(s) => {
                                                engine.session = s;
                                                transcript.clear();
                                                sessions = engine
                                                    .memory
                                                    .list_sessions()
                                                    .unwrap_or_default();
                                                sel = 0;
                                                scroll = 0;
                                                status = "new session created".into();
                                            }
                                            Err(e) => status = format!("error: {e}"),
                                        }
                                    }
                                    "switch" => {
                                        sessions =
                                            engine.memory.list_sessions().unwrap_or_default();
                                        focus = Focus::Sidebar;
                                        status = "sessions — ↑/↓ select, Enter open, n new, r rename, d delete, Tab back".into();
                                    }
                                    "clear" => match engine.session.clear(&engine.memory) {
                                        Ok(()) => {
                                            transcript.clear();
                                            scroll = 0;
                                            status = "session cleared (history wiped)".into();
                                            sessions =
                                                engine.memory.list_sessions().unwrap_or_default();
                                        }
                                        Err(e) => status = format!("error: {e}"),
                                    },
                                    "model" => {
                                        if arg.is_empty() {
                                            status = format!("model: {}", engine.model);
                                        } else {
                                            engine.model = arg.clone();
                                            status =
                                                format!("model switched to {arg} (this run only)");
                                        }
                                    }
                                    "quit" | "exit" => return Ok(()),
                                    "" => status = "type /help for the command list".into(),
                                    other => {
                                        status = format!("unknown command '/{other}' — try /help");
                                    }
                                }
                                continue;
                            }

                            transcript.push(ChatLine {
                                speaker: Speaker::User,
                                text: text.clone(),
                            });
                            transcript.push(ChatLine {
                                speaker: Speaker::Assistant,
                                text: String::new(),
                            });
                            scroll = 0;
                            match engine.stream_reply(&text).await {
                                Ok(stream) => {
                                    active = Some(stream);
                                    buffer.clear();
                                    status = "streaming...".into();
                                    phase = Phase::Streaming;
                                }
                                Err(e) => {
                                    transcript.pop();
                                    status = format!("error: {e}");
                                }
                            }
                        }
                    }
                    Some(Ok(Event::Mouse(m))) => match m.kind {
                        MouseEventKind::ScrollUp => scroll = scroll.saturating_add(1),
                        MouseEventKind::ScrollDown => scroll = scroll.saturating_sub(1),
                        _ => {}
                    },
                    _ => {}
                }
            }
            Phase::Renaming { .. } => {
                let id = match &phase {
                    Phase::Renaming { id } => id.clone(),
                    _ => return Ok(()),
                };
                if let Some(Ok(Event::Key(key))) = events.next().await {
                    if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                        continue;
                    }
                    match key.code {
                        KeyCode::Enter => {
                            let name = input.trim().to_string();
                            if name.is_empty() {
                                status = "name cannot be empty (Esc to cancel)".into();
                            } else {
                                match engine.memory.rename_session(&id, &name) {
                                    Ok(()) => {
                                        sessions =
                                            engine.memory.list_sessions().unwrap_or_default();
                                        status = format!("renamed to '{name}'");
                                        phase = Phase::Idle;
                                        input.clear();
                                        focus = Focus::Sidebar;
                                    }
                                    Err(e) => status = format!("error: {e}"),
                                }
                            }
                        }
                        KeyCode::Esc => {
                            phase = Phase::Idle;
                            input.clear();
                            status = "rename cancelled".into();
                            focus = Focus::Sidebar;
                        }
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            return Ok(());
                        }
                        KeyCode::Backspace => {
                            input.pop();
                        }
                        KeyCode::Char(c) => input.push(c),
                        _ => {}
                    }
                }
            }
        }
    }
}

/// Open the selected sidebar session (no-op when already active).
fn switch_session(
    engine: &mut ChatEngine,
    sessions: &[SessionInfo],
    sel: usize,
    transcript: &mut Vec<ChatLine>,
    status: &mut String,
) -> Result<()> {
    let Some(info) = sessions.get(sel) else {
        *status = "no session selected".into();
        return Ok(());
    };
    if info.id == engine.session.id {
        *status = "already on this session".into();
        return Ok(());
    }
    match crate::core::session::Session::load(&engine.memory, &info.id) {
        Ok(loaded) => {
            *transcript = loaded
                .messages
                .iter()
                .map(|m| ChatLine {
                    speaker: match m.role {
                        Role::User => Speaker::User,
                        Role::Assistant => Speaker::Assistant,
                        Role::System => Speaker::System,
                    },
                    text: m.content.clone(),
                })
                .collect();
            engine.session = loaded;
            *status = format!("opened session '{}'", info.name);
        }
        Err(e) => *status = format!("error: {e}"),
    }
    Ok(())
}

/// Run one approved proposal, render its output and persist it as a tool message.
async fn execute_proposal(
    engine: &mut ChatEngine,
    transcript: &mut Vec<ChatLine>,
    status: &mut String,
    p: &Proposal,
    timeout_secs: u64,
    max_output_bytes: usize,
) -> Result<()> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    match tools::run(&p.command, timeout, max_output_bytes).await {
        Ok(output) => {
            for l in output.render().lines() {
                transcript.push(ChatLine {
                    speaker: Speaker::Tool,
                    text: l.to_string(),
                });
            }
            engine
                .session
                .add_user(&engine.memory, &output.as_tool_message(&p.command))?;
            *status = format!("executed (exit {})", output.code.unwrap_or(-1));
        }
        Err(e) => *status = format!("error: {e}"),
    }
    Ok(())
}

/// Move to the next proposal, or finish the confirmation phase.
fn advance_proposal(phase: &mut Phase, status: &mut String, idx: usize, total: usize) {
    let next = idx + 1;
    if next < total {
        if let Phase::Confirming { idx: i, .. } = phase {
            *i = next;
        }
        *status = format!("proposal {}/{}", next + 1, total);
    } else {
        *phase = Phase::Idle;
        *status = "ready".into();
    }
}

fn delete_word(input: &mut String) {
    while input.ends_with(' ') {
        input.pop();
    }
    while !input.is_empty() && !input.ends_with(' ') {
        input.pop();
    }
}

/// Cursor (column, row) at the end of a possibly multiline input.
fn input_cursor(input: &str) -> (u16, u16) {
    let mut col = 0u16;
    let mut row = 0u16;
    for c in input.chars() {
        if c == '\n' {
            row += 1;
            col = 0;
        } else {
            col += 1;
        }
    }
    (col, row)
}

fn handle_key(key: KeyEvent, input: &mut String) -> KeyAction {
    if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
        return KeyAction::None;
    }
    match (key.code, key.modifiers) {
        (KeyCode::Esc, _) => KeyAction::Quit,
        (KeyCode::Char('c'), KeyModifiers::CONTROL) => KeyAction::Quit,
        (KeyCode::Char('l'), KeyModifiers::CONTROL) => KeyAction::Clear,
        (KeyCode::Char('w'), KeyModifiers::CONTROL) => KeyAction::DeleteWord,
        (KeyCode::Char('u'), KeyModifiers::CONTROL) => {
            input.clear();
            KeyAction::None
        }
        (KeyCode::Tab, _) => KeyAction::ToggleSidebar,
        (KeyCode::Enter, KeyModifiers::ALT) => KeyAction::Newline,
        (KeyCode::Enter, _) => KeyAction::Send,
        (KeyCode::Backspace, _) => {
            input.pop();
            KeyAction::None
        }
        (KeyCode::Char(c), _) => {
            input.push(c);
            KeyAction::None
        }
        (KeyCode::Up, _) | (KeyCode::PageUp, _) => KeyAction::ScrollUp,
        (KeyCode::Down, _) | (KeyCode::PageDown, _) => KeyAction::ScrollDown,
        _ => KeyAction::None,
    }
}

fn handle_proposal_key(key: KeyEvent) -> ProposalAction {
    if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
        return ProposalAction::None;
    }
    match (key.code, key.modifiers) {
        (KeyCode::Char('c'), KeyModifiers::CONTROL) => ProposalAction::Quit,
        (KeyCode::Char('y') | KeyCode::Char('Y'), _) => ProposalAction::Approve,
        (KeyCode::Char('n') | KeyCode::Char('N'), _) => ProposalAction::Deny,
        (KeyCode::Char('a') | KeyCode::Char('A'), _) => ProposalAction::ApproveAll,
        (KeyCode::Char('q') | KeyCode::Char('Q'), _) => ProposalAction::SkipAll,
        (KeyCode::Esc, _) => ProposalAction::SkipAll,
        _ => ProposalAction::None,
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_ui(
    f: &mut Frame,
    engine: &ChatEngine,
    transcript: &[ChatLine],
    input: &str,
    status: &str,
    scroll: u16,
    phase: &Phase,
    focus: Focus,
    sessions: &[SessionInfo],
    sel: usize,
    spinner: &str,
    tools_enabled: bool,
) {
    let area = f.area();

    let main = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .split(area);

    // Header bar (single line, accent background).
    let header = Paragraph::new(format!(
        " enclave  ·  {} · {} · session '{}' · tools {} ",
        engine.provider_name(),
        engine.model,
        engine.session.name,
        if tools_enabled { "on" } else { "off" }
    ))
    .style(
        Style::default()
            .fg(Color::Cyan)
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );
    f.render_widget(header, main[0]);

    // Chat area (full width on narrow terminals).
    let show_sidebar = area.width >= 70 && !sessions.is_empty();
    let chat_area = if show_sidebar {
        let cols = Layout::horizontal([
            Constraint::Length(SIDEBAR_WIDTH),
            Constraint::Min(1),
        ])
        .split(main[1]);
        draw_sidebar(f, cols[0], engine, sessions, sel, focus);
        cols[1]
    } else {
        main[1]
    };

    // Transcript.
    let mut lines: Vec<Line> = Vec::new();
    for entry in transcript {
        match entry.speaker {
            Speaker::User => {
                lines.push(Line::from(vec![
                    Span::styled(format!("{}: ", entry.speaker.label()), Speaker::User.style()),
                    Span::raw(&entry.text),
                ]));
            }
            Speaker::System => {
                lines.push(Line::from(vec![
                    Span::styled(format!("{}: ", entry.speaker.label()), Speaker::System.style()),
                    Span::raw(&entry.text),
                ]));
            }
            Speaker::Tool => {
                for l in entry.text.lines() {
                    lines.push(Line::from(Span::styled(l.to_string(), Speaker::Tool.style())));
                }
            }
            Speaker::Assistant => {
                lines.push(Line::from(Span::styled("assistant:", Speaker::Assistant.style())));
                lines.extend(markdown::render(&entry.text));
                lines.push(Line::from(""));
            }
        }
    }
    let total = lines.len();
    let view_h = chat_area.height.saturating_sub(2) as usize;
    let max_scroll = total.saturating_sub(view_h);
    let offset = max_scroll.saturating_sub(scroll as usize) as u16;
    let chat = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" chat "),
        )
        .wrap(Wrap { trim: false })
        .scroll((offset, 0));
    f.render_widget(chat, chat_area);

    // Bottom panel: proposal prompt while confirming, else the message input.
    match phase {
        Phase::Confirming { proposals, idx, .. } => {
            let p = &proposals[*idx];
            let body = format!(
                "$ {}\n\nrun? [y]es / [n]o / [a]ll / [q]uit   ({}/{})",
                p.command,
                idx + 1,
                proposals.len()
            );
            let warn = Paragraph::new(body)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded)
                        .title(" shell proposal — nothing runs without your approval ")
                        .border_style(Style::default().fg(Color::Yellow)),
                )
                .wrap(Wrap { trim: false });
            f.render_widget(warn, main[2]);
        }
        _ => {
            let renaming = matches!(phase, Phase::Renaming { .. });
            let title = if renaming {
                " rename — Enter confirm · Esc cancel "
            } else if focus == Focus::Sidebar {
                " message (Tab to edit) "
            } else {
                " message "
            };
            let input_widget = Paragraph::new(input.to_string())
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded)
                        .title(title),
                );
            f.render_widget(input_widget, main[2]);
            if focus == Focus::Chat || renaming {
                let (col, row) = input_cursor(input);
                let cursor_x = main[2].x + 1 + col;
                let cursor_y = main[2].y + 1 + row;
                if cursor_x < main[2].x + main[2].width.saturating_sub(1)
                    && cursor_y < main[2].y + main[2].height.saturating_sub(1)
                {
                    f.set_cursor_position(Position {
                        x: cursor_x,
                        y: cursor_y,
                    });
                }
            }
        }
    }

    // Status bar.
    let status_style = if status.starts_with("error") {
        Style::default().fg(Color::Red)
    } else if matches!(phase, Phase::Confirming { .. }) {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().add_modifier(Modifier::DIM)
    };
    let shown_status = if phase_matches_streaming(phase) {
        format!("{spinner} {status}")
    } else {
        status.to_string()
    };
    let scroll_note = if scroll > 0 {
        format!(" | ↑{scroll}")
    } else {
        String::new()
    };
    let hints = if focus == Focus::Sidebar {
        "↑/↓ select · Enter open · n new · r rename · d delete · Tab back"
    } else {
        "Enter send · Alt+Enter newline · Tab sessions · Ctrl-L clear · /help · Esc quit"
    };
    let bar = Paragraph::new(format!(" {shown_status}{scroll_note}  |  {hints} ")).style(status_style);
    f.render_widget(bar, main[3]);
}

fn phase_matches_streaming(phase: &Phase) -> bool {
    matches!(phase, Phase::Streaming)
}

/// Render the sessions sidebar.
fn draw_sidebar(
    f: &mut Frame,
    area: ratatui::layout::Rect,
    engine: &ChatEngine,
    sessions: &[SessionInfo],
    sel: usize,
    focus: Focus,
) {
    let items: Vec<ListItem> = sessions
        .iter()
        .map(|s| {
            let marker = if s.id == engine.session.id { "●" } else { "○" };
            ListItem::new(format!("{marker} {} ({})", s.name, s.message_count))
        })
        .collect();
    let title = if focus == Focus::Sidebar {
        " sessions ◆ "
    } else {
        " sessions "
    };
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(title)
                .border_style(if focus == Focus::Sidebar {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default()
                }),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    let mut state = ListState::default();
    state.select(Some(sel.min(sessions.len().saturating_sub(1))));
    f.render_stateful_widget(list, area, &mut state);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_word_removes_last_token() {
        let mut s = String::from("hello world");
        delete_word(&mut s);
        assert_eq!(s, "hello ");
        delete_word(&mut s);
        assert_eq!(s, "");
        delete_word(&mut s); // must not panic on empty
        assert_eq!(s, "");
    }

    #[test]
    fn input_cursor_tracks_multiline() {
        assert_eq!(input_cursor(""), (0, 0));
        assert_eq!(input_cursor("ciao"), (4, 0));
        assert_eq!(input_cursor("ciao\n"), (0, 1));
        assert_eq!(input_cursor("prima riga\nseconda"), (7, 1));
        assert_eq!(input_cursor("a\nb\nc"), (1, 2));
    }

    #[test]
    fn alt_enter_is_newline_not_send() {
        use crossterm::event::{KeyCode, KeyModifiers};
        let alt = KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT);
        assert!(matches!(handle_key(alt, &mut String::new()), KeyAction::Newline));
        let plain = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        assert!(matches!(handle_key(plain, &mut String::new()), KeyAction::Send));
    }

    #[test]
    fn proposal_keys_map_to_actions() {
        use crossterm::event::{KeyCode, KeyModifiers};
        let press = |c: char| KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
        assert!(matches!(
            handle_proposal_key(press('y')),
            ProposalAction::Approve
        ));
        assert!(matches!(handle_proposal_key(press('n')), ProposalAction::Deny));
        assert!(matches!(
            handle_proposal_key(press('a')),
            ProposalAction::ApproveAll
        ));
        assert!(matches!(
            handle_proposal_key(press('q')),
            ProposalAction::SkipAll
        ));
        assert!(matches!(
            handle_proposal_key(press('x')),
            ProposalAction::None
        ));
        assert!(matches!(
            handle_proposal_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            ProposalAction::SkipAll
        ));
    }

    #[test]
    fn advance_moves_through_proposals_then_idle() {
        let mut phase = Phase::Confirming {
            proposals: vec![],
            idx: 0,
            approve_all: false,
        };
        let mut status = String::new();
        advance_proposal(&mut phase, &mut status, 0, 3);
        assert!(matches!(&phase, Phase::Confirming { idx: 1, .. }));
        assert_eq!(status, "proposal 2/3");
        advance_proposal(&mut phase, &mut status, 2, 3);
        assert!(matches!(phase, Phase::Idle));
        assert_eq!(status, "ready");
    }
}
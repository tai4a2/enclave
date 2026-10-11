//! Full-screen terminal UI built on ratatui (opencode-style layout).

use std::io::{Stdout, stdout};
use std::path::Path;
use std::time::Duration;

use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use futures::StreamExt;
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Padding, Paragraph, Wrap};

use crate::config::{GuardMode, GuardSettings, ToolsSettings};
use crate::core::engine::ChatEngine;
use crate::core::attachment::Attachment;
use crate::core::message::{Role, ToolCall};
use crate::core::builtin_tools::FileChange;
use crate::core::engine::{AgentStep, ApprovedGate};
use crate::core::tools::{self, Proposal};
use crate::error::Result;
use crate::privacy::SessionInfo;
use crate::privacy::guard::{self, Finding, Redactor};
use crate::privacy::SecureCredentials;
use crate::providers::{ChunkStream, OpenRouterAccount, OpenRouterModel};
use crate::tui::markdown;

/// Sidebar width in cells; hidden on narrow terminals.
const SIDEBAR_WIDTH: u16 = 28;
const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Reasoning-effort choices offered by the effort picker (value, description).
const EFFORT_OPTIONS: &[(&str, &str)] = &[
    ("default", "use the model default"),
    ("low", "fastest, cheapest"),
    ("medium", "balanced"),
    ("high", "deepest reasoning"),
];

// --- Theme -----------------------------------------------------------------
// A dark, professional palette. Panels are separated by subtle background
// shades (no hard borders): the transcript sits on the base background while
// the header, sidebar, info panel, input and footer use a slightly lighter
// surface colour.
const C_BG: Color = Color::Rgb(17, 18, 22);
const C_SURFACE: Color = Color::Rgb(30, 31, 37);
const C_SURFACE_HI: Color = Color::Rgb(44, 46, 54);
const C_TEXT: Color = Color::Rgb(226, 226, 232);
const C_DIM: Color = Color::Rgb(132, 134, 148);
const C_ACCENT: Color = Color::Rgb(167, 139, 250); // soft violet
const C_GREEN: Color = Color::Rgb(134, 239, 172);
const C_RED: Color = Color::Rgb(248, 150, 150);
const C_YELLOW: Color = Color::Rgb(250, 220, 120);

/// Full-row surface style used for header/footer bars.
fn surface() -> Style {
    Style::default().bg(C_SURFACE)
}

/// Text shown by `/help`.
const SLASH_HELP: &str =
    "commands: /help · /new · /switch · /clear · /model [id] (no id opens the model picker; the choice is saved) · /effort [off|low|medium|high] · /attach <path> · /detach · /credits · /quit   (Ctrl-S = session picker)";

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

/// What the app is currently doing.
enum Phase {
    Idle,
    Streaming,
    Confirming {
        proposals: Vec<Proposal>,
        idx: usize,
        approve_all: bool,
    },
    /// Agentic mode: built-in tool calls awaiting approval.
    ToolConfirm {
        calls: Vec<ToolCall>,
        idx: usize,
        approve_all: bool,
    },
    /// Privacy guard found sensitive data in the message about to be sent.
    Guard {
        text: String,
        findings: Vec<Finding>,
    },
    /// Renaming a session (`Some(id)`) or naming a brand-new one (`None`).
    /// The message input collects the name.
    Renaming {
        id: Option<String>,
    },
}

/// Session-scoped privacy-guard decision (never persisted).
#[derive(Clone, Copy, PartialEq)]
enum GuardDecision {
    Undecided,
    Approved,
    Redacted,
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
    /// '?' with empty input: toggle the shortcuts overlay.
    Help,
    /// Ctrl+S: open the session picker overlay.
    SessionPicker,
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
pub async fn run(
    mut engine: ChatEngine,
    tools_cfg: ToolsSettings,
    guard_cfg: GuardSettings,
    agent: bool,
) -> Result<()> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    let result = run_app(&mut engine, tools_cfg, guard_cfg, agent, &mut terminal).await;

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
    guard_cfg: GuardSettings,
    agent: bool,
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
                Role::Tool => Speaker::Tool,
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
    let mut help = false;
    let mut picker = false;
    let mut model_picker = false;
    let mut model_entries: Vec<(String, String)> = Vec::new();
    let mut model_filter = String::new();
    let mut model_sel: usize = 0;
    let mut effort_picker = false;
    let mut effort_sel: usize = engine
        .reasoning_effort
        .as_deref()
        .and_then(|e| EFFORT_OPTIONS.iter().position(|(v, _)| *v == e))
        .unwrap_or(0);
    let mut guard_decision = GuardDecision::Undecided;
    let mut account: Option<OpenRouterAccount> = None;
    // Silent, prompt-free credit fetch when the API key comes from the
    // environment (no keychain dialog). Otherwise it is fetched on demand.
    if engine.provider_name() == "openrouter" {
        if let Some(key) = SecureCredentials::local_api_key("openrouter") {
            if let Ok(acc) = OpenRouterAccount::fetch(&key).await {
                account = Some(acc);
            }
        }
    }
    let mut privacy = privacy_snapshot(engine, &guard_cfg);
    let mut tick_count: u64 = 0;
    let mut changes: Vec<FileChange> = Vec::new();
    // Files attached to the next message (see /attach).
    let mut pending: Vec<Attachment> = Vec::new();
    let agent_mode = agent;
    let mut agent_iters: usize = 0;
    let defs = crate::core::builtin_tools::defs(false);
    let ctx = crate::core::builtin_tools::ToolContext {
        workspace: std::env::current_dir().unwrap_or_default(),
        shell_timeout_secs: tools_cfg.timeout_secs,
        max_output_bytes: tools_cfg.max_output_bytes,
        delegate: None,
    };

    loop {
        let guard_state = if !guard_cfg.enabled {
            "off"
        } else {
            match guard_decision {
                GuardDecision::Undecided => "on",
                GuardDecision::Approved => "approved",
                GuardDecision::Redacted => "placeholders",
            }
        };
        terminal.draw(|f| {
            let atts_label = attachments_label(&pending);
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
                guard_state,
                help,
                picker,
                model_picker,
                &model_entries,
                &model_filter,
                model_sel,
                effort_picker,
                effort_sel,
                &privacy,
                account.as_ref(),
                &changes,
                &atts_label,
            )
        })?;

        match phase {
            Phase::Streaming => {
                let mut outcome: Option<ChunkOutcome> = None;
                tokio::select! {
                    _ = tick.tick() => {
                        spinner_idx = (spinner_idx + 1) % SPINNER.len();
                        tick_count = tick_count.wrapping_add(1);
                        if tick_count.is_multiple_of(16) {
                            privacy = privacy_snapshot(engine, &guard_cfg);
                        }
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
                        let empty = content.trim().is_empty();
                        match engine.commit_assistant(content) {
                            Ok(()) if empty => {
                                status =
                                    "empty response — model returned no text (try /model)".into()
                            }
                            Ok(()) => status = "ready".into(),
                            Err(e) => status = format!("commit error: {e}"),
                        }
                        active = None;
                        privacy = privacy_snapshot(engine, &guard_cfg);

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
            Phase::ToolConfirm { .. } => {
                let (call, idx, total, approve_all) = match &phase {
                    Phase::ToolConfirm {
                        calls,
                        idx,
                        approve_all,
                    } => (calls.get(*idx).cloned(), *idx, calls.len(), *approve_all),
                    _ => (None, 0, 0, false),
                };

                // "all" already approved: run without waiting for keys.
                if approve_all {
                    if let Some(c) = &call {
                        agentic_approve(engine, &mut transcript, &mut changes, &ctx, c).await?;
                    }
                    if !advance_tool(&mut phase, &mut status, idx, total) {
                        agentic_advance(
                            engine,
                            &mut transcript,
                            &mut status,
                            &mut phase,
                            &mut changes,
                            &mut agent_iters,
                            &defs,
                            &ctx,
                        )
                        .await?;
                    }
                    continue;
                }

                if let Some(Ok(Event::Key(key))) = events.next().await {
                    if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                        continue;
                    }
                    match key.code {
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            return Ok(());
                        }
                        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
                            if let Some(c) = &call {
                                engine.push_tool_result(&c.id, "[skipped by user]")?;
                            }
                            status = "tools skipped".into();
                            phase = Phase::Idle;
                        }
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            if let Some(c) = &call {
                                agentic_approve(engine, &mut transcript, &mut changes, &ctx, c)
                                    .await?;
                            }
                            if !advance_tool(&mut phase, &mut status, idx, total) {
                                agentic_advance(
                                    engine,
                                    &mut transcript,
                                    &mut status,
                                    &mut phase,
                                    &mut changes,
                                    &mut agent_iters,
                                    &defs,
                                    &ctx,
                                )
                                .await?;
                            }
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') => {
                            if let Some(c) = &call {
                                engine.push_tool_result(&c.id, "[denied by user]")?;
                            }
                            if !advance_tool(&mut phase, &mut status, idx, total) {
                                agentic_advance(
                                    engine,
                                    &mut transcript,
                                    &mut status,
                                    &mut phase,
                                    &mut changes,
                                    &mut agent_iters,
                                    &defs,
                                    &ctx,
                                )
                                .await?;
                            }
                        }
                        KeyCode::Char('a') | KeyCode::Char('A') => {
                            if let Some(c) = &call {
                                agentic_approve(engine, &mut transcript, &mut changes, &ctx, c)
                                    .await?;
                            }
                            if let Phase::ToolConfirm { approve_all, .. } = &mut phase {
                                *approve_all = true;
                            }
                            if !advance_tool(&mut phase, &mut status, idx, total) {
                                agentic_advance(
                                    engine,
                                    &mut transcript,
                                    &mut status,
                                    &mut phase,
                                    &mut changes,
                                    &mut agent_iters,
                                    &defs,
                                    &ctx,
                                )
                                .await?;
                            }
                        }
                        _ => {}
                    }
                }
            }
            Phase::Idle => {
                match events.next().await {
                    Some(Ok(Event::Key(key))) => {
                        if model_picker {
                            if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                                continue;
                            }
                            let filtered = filter_entries(&model_entries, &model_filter);
                            let last = filtered.len().saturating_sub(1);
                            match (key.code, key.modifiers) {
                                (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Ok(()),
                                (KeyCode::Up, _) => model_sel = model_sel.saturating_sub(1),
                                (KeyCode::Down, _) => model_sel = (model_sel + 1).min(last),
                                (KeyCode::PageUp, _) => model_sel = model_sel.saturating_sub(10),
                                (KeyCode::PageDown, _) => model_sel = (model_sel + 10).min(last),
                                (KeyCode::Home, _) => model_sel = 0,
                                (KeyCode::End, _) => model_sel = last,
                                (KeyCode::Char('u'), KeyModifiers::CONTROL) => {
                                    model_filter.clear();
                                    model_sel = 0;
                                }
                                (KeyCode::Enter, _) => {
                                    if let Some(&i) = filtered.get(model_sel) {
                                        engine.model = model_entries[i].0.clone();
                                        persist_model(&engine.model);
                                        status = format!(
                                            "model {} (saved) — now pick the reasoning effort",
                                            engine.model
                                        );
                                        model_picker = false;
                                        effort_sel = engine
                                            .reasoning_effort
                                            .as_deref()
                                            .and_then(|e| {
                                                EFFORT_OPTIONS.iter().position(|(v, _)| *v == e)
                                            })
                                            .unwrap_or(0);
                                        effort_picker = true;
                                    } else {
                                        model_picker = false;
                                    }
                                }
                                (KeyCode::Esc, _) => {
                                    model_picker = false;
                                    status = "ready".into();
                                }
                                (KeyCode::Backspace, _) => {
                                    model_filter.pop();
                                    model_sel = 0;
                                }
                                (KeyCode::Char(c), _) => {
                                    model_filter.push(c);
                                    model_sel = 0;
                                }
                                _ => {}
                            }
                            continue;
                        }
                        if effort_picker {
                            if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                                continue;
                            }
                            let last = EFFORT_OPTIONS.len() - 1;
                            match (key.code, key.modifiers) {
                                (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Ok(()),
                                (KeyCode::Up, _) => effort_sel = effort_sel.saturating_sub(1),
                                (KeyCode::Down, _) => effort_sel = (effort_sel + 1).min(last),
                                (KeyCode::Home, _) => effort_sel = 0,
                                (KeyCode::End, _) => effort_sel = last,
                                (KeyCode::Enter, _) => {
                                    let (label, _) = EFFORT_OPTIONS[effort_sel.min(last)];
                                    let value = if label == "default" {
                                        None
                                    } else {
                                        Some(label.to_string())
                                    };
                                    engine.reasoning_effort = value.clone();
                                    persist_effort(value.as_deref());
                                    status = format!("reasoning effort: {label} (saved)");
                                    effort_picker = false;
                                }
                                (KeyCode::Esc, _) => {
                                    effort_picker = false;
                                    status = "effort unchanged".into();
                                }
                                _ => {}
                            }
                            continue;
                        }
                        if picker {
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
                                    picker = false;
                                }
                                KeyCode::Char('c')
                                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                                {
                                    return Ok(());
                                }
                                KeyCode::Char('n') => {
                                    picker = false;
                                    phase = Phase::Renaming { id: None };
                                    input.clear();
                                    status = "new session — type a name (empty = 'chat')".into();
                                }
                                KeyCode::Char('r') => {
                                    if let Some(info) = sessions.get(sel) {
                                        picker = false;
                                        input = info.name.clone();
                                        phase =
                                            Phase::Renaming { id: Some(info.id.clone()) };
                                        status = format!("renaming '{}'", info.name);
                                    }
                                }
                                KeyCode::Char('d') => {
                                    match sessions
                                        .get(sel)
                                        .map(|s| (s.id.clone(), s.name.clone()))
                                    {
                                        Some((id, _)) if id == engine.session.id => {
                                            status = "cannot delete the active session".into();
                                        }
                                        Some((id, name)) => {
                                            let _ = engine.memory.delete_session(&id);
                                            sessions = engine
                                                .memory
                                                .list_sessions()
                                                .unwrap_or_default();
                                            sel = sel.min(sessions.len().saturating_sub(1));
                                            status = format!("deleted '{name}'");
                                        }
                                        None => {}
                                    }
                                }
                                KeyCode::Esc
                                | KeyCode::Char('s')
                                | KeyCode::Char('q') => {
                                    picker = false;
                                    status = "ready".into();
                                }
                                _ => {}
                            }
                            continue;
                        }
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
                                    phase = Phase::Renaming { id: None };
                                    input.clear();
                                    status =
                                        "new session — type a name (empty = 'chat'), Enter confirms, Esc cancels"
                                            .into();
                                }
                                KeyCode::Char('r') => match sessions.get(sel) {
                                    Some(info) => {
                                        input = info.name.clone();
                                        phase = Phase::Renaming {
                                            id: Some(info.id.clone()),
                                        };
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

                        if help {
                            // Any key closes the shortcuts overlay.
                            help = false;
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
                                    privacy = privacy_snapshot(engine, &guard_cfg);
                                }
                                Err(e) => status = format!("error: {e}"),
                            },
                            KeyAction::Send => send = true,
                            KeyAction::ScrollUp => scroll = scroll.saturating_add(1),
                            KeyAction::ScrollDown => scroll = scroll.saturating_sub(1),
                            KeyAction::DeleteWord => delete_word(&mut input),
                            KeyAction::Newline => input.push('\n'),
                            KeyAction::Help => help = true,
                            KeyAction::ToggleSidebar => {
                                sessions = engine.memory.list_sessions().unwrap_or_default();
                                focus = Focus::Sidebar;
                                status =
                                    "sessions — ↑/↓ select, Enter open, n new, r rename, d delete, Tab back".into();
                            }
                            KeyAction::SessionPicker => {
                                sessions = engine.memory.list_sessions().unwrap_or_default();
                                picker = true;
                                status = "session picker — ↑/↓ select, Enter open, n new, r rename, d delete, Esc close".into();
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
                                        phase = Phase::Renaming { id: None };
                                        input.clear();
                                        status =
                                            "new session — type a name (empty = 'chat'), Enter confirms, Esc cancels"
                                                .into();
                                    }
                                    "switch" => {
                                        sessions =
                                            engine.memory.list_sessions().unwrap_or_default();
                                        picker = true;
                                        status = "session picker — ↑/↓ select, Enter open, n new, r rename, d delete, Esc close".into();
                                    }
                                    "clear" => match engine.session.clear(&engine.memory) {
                                        Ok(()) => {
                                            transcript.clear();
                                            scroll = 0;
                                            status = "session cleared (history wiped)".into();
                                            sessions =
                                                engine.memory.list_sessions().unwrap_or_default();
                                            privacy = privacy_snapshot(engine, &guard_cfg);
                                        }
                                        Err(e) => status = format!("error: {e}"),
                                    },
                                    "model" | "models" => {
                                        if !arg.is_empty() {
                                            engine.model = arg.clone();
                                            persist_model(&arg);
                                            status = format!("model switched to {arg} (saved)");
                                        } else {
                                            open_model_picker(
                                                engine,
                                                &mut model_entries,
                                                &mut model_filter,
                                                &mut model_sel,
                                                &mut account,
                                                &mut status,
                                            )
                                            .await;
                                            model_picker = true;
                                        }
                                    }
                                    "effort" => {
                                        let v = arg.to_ascii_lowercase();
                                        match v.as_str() {
                                            "" => {
                                                effort_sel = engine
                                                    .reasoning_effort
                                                    .as_deref()
                                                    .and_then(|e| {
                                                        EFFORT_OPTIONS
                                                            .iter()
                                                            .position(|(v, _)| *v == e)
                                                    })
                                                    .unwrap_or(0);
                                                effort_picker = true;
                                                status = "effort picker — ↑/↓ select, Enter choose, Esc close".into();
                                            }
                                            "off" | "none" | "default" => {
                                                engine.reasoning_effort = None;
                                                persist_effort(None);
                                                status = "reasoning effort: default".into();
                                            }
                                            "low" | "medium" | "high" => {
                                                engine.reasoning_effort = Some(v.clone());
                                                persist_effort(Some(&v));
                                                status = format!("reasoning effort: {v} (saved)");
                                            }
                                            other => {
                                                status = format!(
                                                    "unknown effort '{other}' — use off|low|medium|high"
                                                );
                                            }
                                        }
                                    }
                                    "credits" | "usage" => {
                                        if engine.provider_name() != "openrouter" {
                                            status =
                                                "account info is only available for OpenRouter".into();
                                        } else if let Some(key) =
                                            SecureCredentials::local_api_key("openrouter")
                                        {
                                            match OpenRouterAccount::fetch(&key).await {
                                                Ok(acc) => {
                                                    transcript.push(ChatLine {
                                                        speaker: Speaker::System,
                                                        text: acc.report(),
                                                    });
                                                    status = acc.summary();
                                                    account = Some(acc);
                                                }
                                                Err(e) => status = format!("error: {e}"),
                                            }
                                        } else {
                                            status =
                                                "no OpenRouter key in env or keys.toml — run: enclave keys set openrouter".into();
                                        }
                                    }
                                    "attach" | "file" => {
                                        if arg.is_empty() {
                                            status =
                                                "usage: /attach <path>  (image or text file)".into();
                                        } else {
                                            match Attachment::from_file(Path::new(arg.trim())) {
                                                Ok(a) => {
                                                    let what =
                                                        if a.is_image() { "image" } else { "text" };
                                                    status = format!(
                                                        "attached {what} '{}' — now send your message",
                                                        a.name
                                                    );
                                                    pending.push(a);
                                                }
                                                Err(e) => status = format!("attach failed: {e}"),
                                            }
                                        }
                                    }
                                    "detach" => {
                                        if pending.is_empty() {
                                            status = "no attachments to clear".into();
                                        } else {
                                            let n = pending.len();
                                            pending.clear();
                                            status = format!("cleared {n} attachment(s)");
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

                            // Privacy guard: scan before anything leaves the machine.
                            if guard_cfg.enabled {
                                let mut scan_input = text.clone();
                                for a in &pending {
                                    if let Some(body) = a.text_body() {
                                        scan_input.push('\n');
                                        scan_input.push_str(body);
                                    }
                                }
                                let findings = guard::scan(&scan_input);
                                if !findings.is_empty() {
                                    match guard_decision {
                                        GuardDecision::Approved => {} // send as-is
                                        GuardDecision::Redacted => {} // engine.redactor handles it
                                        GuardDecision::Undecided => match guard_cfg.mode {
                                            GuardMode::Ask => {
                                                phase = Phase::Guard {
                                                    text: text.clone(),
                                                    findings,
                                                };
                                                continue;
                                            }
                                            GuardMode::Redact => {
                                                engine.redactor = Some(Redactor::new());
                                                guard_decision = GuardDecision::Redacted;
                                                status = format!(
                                                    "privacy guard: {} item(s) replaced with placeholders",
                                                    findings.len()
                                                );
                                            }
                                            GuardMode::Block => {
                                                input = text;
                                                status = format!(
                                                    "blocked by privacy guard ({} item(s)) — mode: block",
                                                    findings.len()
                                                );
                                                continue;
                                            }
                                        },
                                    }
                                }
                            }

                            let atts = std::mem::take(&mut pending);
                            if agent_mode && tools_cfg.enabled {
                                begin_agentic_turn(
                                    engine,
                                    &mut transcript,
                                    &mut status,
                                    &mut phase,
                                    &mut changes,
                                    &mut agent_iters,
                                    &defs,
                                    &ctx,
                                    &text,
                                    atts,
                                )
                                .await?;
                            } else {
                                begin_send(
                                    engine,
                                    &mut transcript,
                                    &mut status,
                                    &mut scroll,
                                    &mut phase,
                                    &mut active,
                                    &mut buffer,
                                    &text,
                                    atts,
                                )
                                .await?;
                            }
                        }
                    }
                    Some(Ok(Event::Mouse(m))) => {
                        if model_picker {
                            let filtered = filter_entries(&model_entries, &model_filter);
                            let last = filtered.len().saturating_sub(1);
                            match m.kind {
                                MouseEventKind::ScrollUp => {
                                    model_sel = model_sel.saturating_sub(1)
                                }
                                MouseEventKind::ScrollDown => {
                                    model_sel = (model_sel + 1).min(last)
                                }
                                _ => {}
                            }
                            continue;
                        }
                        match m.kind {
                            MouseEventKind::ScrollUp => scroll = scroll.saturating_add(1),
                            MouseEventKind::ScrollDown => scroll = scroll.saturating_sub(1),
                            MouseEventKind::Down(MouseButton::Left) => {
                                let width = terminal.size().map(|r| r.width).unwrap_or(0);
                                let show_sidebar = width >= 70 && !sessions.is_empty();
                                if show_sidebar && m.column < SIDEBAR_WIDTH && m.row >= 2 {
                                    let idx = (m.row - 2) as usize;
                                    if idx < sessions.len() {
                                        sel = idx;
                                        focus = Focus::Sidebar;
                                        switch_session(
                                            engine,
                                            &sessions,
                                            sel,
                                            &mut transcript,
                                            &mut status,
                                        )?;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            Phase::Guard { .. } => {
                // Sensitive data found: the overlay asks what to do.
                let (text, findings) = match &phase {
                    Phase::Guard { text, findings } => (text.clone(), findings.clone()),
                    _ => (String::new(), Vec::new()),
                };
                if let Some(Ok(Event::Key(key))) = events.next().await {
                    if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                        continue;
                    }
                    match (key.code, key.modifiers) {
                        (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Ok(()),
                        (KeyCode::Char('s') | KeyCode::Char('S'), _) => {
                            guard_decision = GuardDecision::Approved;
                            status = "privacy guard: approved for this session".into();
                            phase = Phase::Idle;
                            begin_send(
                                engine,
                                &mut transcript,
                                &mut status,
                                &mut scroll,
                                &mut phase,
                                &mut active,
                                &mut buffer,
                                &text,
                                std::mem::take(&mut pending),
                            )
                            .await?;
                        }
                        (KeyCode::Char('p') | KeyCode::Char('P'), _) => {
                            engine.redactor = Some(Redactor::new());
                            guard_decision = GuardDecision::Redacted;
                            status = format!(
                                "privacy guard: {} item(s) → placeholders (session-wide)",
                                findings.len()
                            );
                            phase = Phase::Idle;
                            begin_send(
                                engine,
                                &mut transcript,
                                &mut status,
                                &mut scroll,
                                &mut phase,
                                &mut active,
                                &mut buffer,
                                &text,
                                std::mem::take(&mut pending),
                            )
                            .await?;
                        }
                        (KeyCode::Char('r') | KeyCode::Char('R'), _) | (KeyCode::Esc, _) => {
                            input = text;
                            status = "message not sent — you can edit it".into();
                            phase = Phase::Idle;
                        }
                        _ => {}
                    }
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
                            match &id {
                                Some(id) => {
                                    if name.is_empty() {
                                        status = "name cannot be empty (Esc to cancel)".into();
                                    } else {
                                        match engine.memory.rename_session(id, &name) {
                                            Ok(()) => {
                                                sessions = engine
                                                    .memory
                                                    .list_sessions()
                                                    .unwrap_or_default();
                                                status = format!("renamed to '{name}'");
                                                phase = Phase::Idle;
                                                input.clear();
                                                focus = Focus::Sidebar;
                                            }
                                            Err(e) => status = format!("error: {e}"),
                                        }
                                    }
                                }
                                None => {
                                    let name = if name.is_empty() {
                                        "chat".to_string()
                                    } else {
                                        name
                                    };
                                    match crate::core::session::Session::create(
                                        &engine.memory,
                                        &name,
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
                                            status = format!("created session '{name}'");
                                            phase = Phase::Idle;
                                            input.clear();
                                            privacy = privacy_snapshot(engine, &guard_cfg);
                                        }
                                        Err(e) => status = format!("error: {e}"),
                                    }
                                }
                            }
                        }
                        KeyCode::Esc => {
                            phase = Phase::Idle;
                            input.clear();
                            status = "cancelled".into();
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

/// Build the model catalogue for the current provider and open the picker.
async fn open_model_picker(
    engine: &ChatEngine,
    entries: &mut Vec<(String, String)>,
    filter: &mut String,
    sel: &mut usize,
    account: &mut Option<OpenRouterAccount>,
    status: &mut String,
) {
    entries.clear();
    filter.clear();

    if engine.provider_name() == "openrouter" {
        *status = "loading models from openrouter…".into();
        match OpenRouterModel::fetch_all().await {
            Ok(models) if !models.is_empty() => {
                for m in models {
                    let meta = if m.is_free() {
                        format!("FREE · {}k ctx", m.context_length / 1000)
                    } else {
                        format!(
                            "{}k ctx · ${:.2}/${:.2} per M",
                            m.context_length / 1000,
                            m.prompt_price,
                            m.completion_price
                        )
                    };
                    entries.push((m.id, meta));
                }
            }
            Ok(_) => {}
            Err(e) => *status = format!("could not load model list: {e}"),
        }
        // Refresh account/credit info without touching the keychain: only
        // environment variables or the local keys.toml are used.
        if let Some(key) = SecureCredentials::local_api_key("openrouter") {
            if let Ok(acc) = OpenRouterAccount::fetch(&key).await {
                *account = Some(acc);
            }
        }
    }

    if entries.is_empty() {
        for id in crate::providers::suggested_models(engine.provider_name()) {
            entries.push((id.to_string(), "suggested".into()));
        }
    }

    // Always keep the current model visible and selectable.
    if !entries.iter().any(|(id, _)| id == &engine.model) {
        entries.insert(0, (engine.model.clone(), "current".into()));
    }
    *sel = entries
        .iter()
        .position(|(id, _)| id == &engine.model)
        .unwrap_or(0);
    if !status.starts_with("could not load") {
        *status = format!(
            "model picker — type to filter, ↑/↓ select, Enter choose, Esc close ({} available)",
            entries.len()
        );
    }
}

/// Indices of entries matching the (case-insensitive) filter, in order.
fn filter_entries(entries: &[(String, String)], filter: &str) -> Vec<usize> {
    let f = filter.trim().to_lowercase();
    entries
        .iter()
        .enumerate()
        .filter(|(_, (id, meta))| {
            f.is_empty() || id.to_lowercase().contains(&f) || meta.to_lowercase().contains(&f)
        })
        .map(|(i, _)| i)
        .collect()
}

/// Visible window `(start, end)` for a scrollable list, keeping the selection
/// roughly centred and never letting it fall outside the window.
fn list_window(len: usize, sel: usize, visible: usize) -> (usize, usize) {
    if visible == 0 {
        return (0, 0);
    }
    if len <= visible {
        return (0, len);
    }
    let start = sel.saturating_sub(visible / 2).min(len - visible);
    let start = start.min(sel); // never scroll past the selection
    (start, (start + visible).min(len))
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
                        Role::Tool => Speaker::Tool,
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

/// Footer label summarising pending attachments (empty when none).
fn attachments_label(pending: &[Attachment]) -> String {
    if pending.is_empty() {
        return String::new();
    }
    let names: Vec<&str> = pending.iter().map(|a| a.name.as_str()).collect();
    format!("📎 {}", names.join(" · "))
}

/// Transcript text for a user message, annotated with attachment names.
fn user_display(text: &str, attachments: &[Attachment]) -> String {
    if attachments.is_empty() {
        return text.to_string();
    }
    let names: Vec<&str> = attachments.iter().map(|a| a.name.as_str()).collect();
    format!("{text}\n\n📎 {}", names.join(", "))
}

/// Start an agentic turn: persist the user input and ask the model for the
/// first tool round.
#[allow(clippy::too_many_arguments)]
async fn begin_agentic_turn(
    engine: &mut ChatEngine,
    transcript: &mut Vec<ChatLine>,
    status: &mut String,
    phase: &mut Phase,
    changes: &mut Vec<FileChange>,
    agent_iters: &mut usize,
    defs: &[crate::providers::ToolDef],
    ctx: &crate::core::builtin_tools::ToolContext,
    text: &str,
    attachments: Vec<Attachment>,
) -> Result<()> {
    transcript.push(ChatLine {
        speaker: Speaker::User,
        text: user_display(text, &attachments),
    });
    engine.begin_agentic_with(text, attachments)?;
    *agent_iters = 0;
    *status = format!("{} working… (agent)", engine.provider_name());
    agentic_advance(engine, transcript, status, phase, changes, agent_iters, defs, ctx).await
}

/// Ask the provider for the next step and react to it.
#[allow(clippy::too_many_arguments)]
async fn agentic_advance(
    engine: &mut ChatEngine,
    transcript: &mut Vec<ChatLine>,
    status: &mut String,
    phase: &mut Phase,
    _changes: &mut Vec<FileChange>,
    agent_iters: &mut usize,
    defs: &[crate::providers::ToolDef],
    _ctx: &crate::core::builtin_tools::ToolContext,
) -> Result<()> {
    *agent_iters += 1;
    if *agent_iters > 8 {
        *status = "error: agent loop did not converge (8 steps)".into();
        *phase = Phase::Idle;
        return Ok(());
    }
    match engine.agentic_step(defs).await {
        Ok(AgentStep::Final(text)) => {
            if !text.is_empty() {
                transcript.push(ChatLine {
                    speaker: Speaker::Assistant,
                    text,
                });
            }
            *status = "ready".into();
            *phase = Phase::Idle;
        }
        Ok(AgentStep::ToolCalls { text, calls }) => {
            if !text.trim().is_empty() {
                transcript.push(ChatLine {
                    speaker: Speaker::Assistant,
                    text,
                });
            }
            *status = "tool call — approve with y/n/a/q".into();
            *phase = Phase::ToolConfirm {
                calls,
                idx: 0,
                approve_all: false,
            };
        }
        Err(e) => {
            *status = format!("error: {e}");
            *phase = Phase::Idle;
        }
    }
    Ok(())
}

/// Execute one approved tool call, render its output and persist the result.
async fn agentic_approve(
    engine: &mut ChatEngine,
    transcript: &mut Vec<ChatLine>,
    changes: &mut Vec<FileChange>,
    ctx: &crate::core::builtin_tools::ToolContext,
    call: &ToolCall,
) -> Result<()> {
    let mut gate = ApprovedGate;
    match crate::core::builtin_tools::execute_detailed(call, ctx, &mut gate).await {
        Ok(out) => {
            for line in out.text.lines() {
                transcript.push(ChatLine {
                    speaker: Speaker::Tool,
                    text: line.to_string(),
                });
            }
            if let Some(ch) = out.change {
                changes.push(ch);
            }
            engine.push_tool_result(&call.id, &out.text)?;
        }
        Err(e) => {
            let msg = format!("[tool error] {e}");
            transcript.push(ChatLine {
                speaker: Speaker::Tool,
                text: msg.clone(),
            });
            engine.push_tool_result(&call.id, &msg)?;
        }
    }
    Ok(())
}

/// Move to the next pending tool call. Returns true if there is one.
fn advance_tool(phase: &mut Phase, status: &mut String, idx: usize, total: usize) -> bool {
    if idx + 1 < total {
        if let Phase::ToolConfirm { idx: i, .. } = phase {
            *i = idx + 1;
        }
        *status = format!("tool call {}/{} — approve with y/n/a/q", idx + 2, total);
        true
    } else {
        false
    }
}

#[allow(clippy::too_many_arguments)]
/// Push the user line and start streaming the assistant reply.
async fn begin_send(
    engine: &mut ChatEngine,
    transcript: &mut Vec<ChatLine>,
    status: &mut String,
    scroll: &mut u16,
    phase: &mut Phase,
    active: &mut Option<ChunkStream>,
    buffer: &mut String,
    text: &str,
    attachments: Vec<Attachment>,
) -> Result<()> {
    transcript.push(ChatLine {
        speaker: Speaker::User,
        text: user_display(text, &attachments),
    });
    transcript.push(ChatLine {
        speaker: Speaker::Assistant,
        text: String::new(),
    });
    *scroll = 0;
    match engine.stream_reply_with(text, attachments).await {
        Ok(stream) => {
            *active = Some(stream);
            buffer.clear();
            *status = "streaming...".into();
            *phase = Phase::Streaming;
        }
        Err(e) => {
            transcript.pop();
            *status = format!("error: {e}");
        }
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
        (KeyCode::Char('s'), KeyModifiers::CONTROL) => KeyAction::SessionPicker,
        (KeyCode::Tab, _) => KeyAction::ToggleSidebar,
        (KeyCode::Enter, KeyModifiers::ALT) => KeyAction::Newline,
        (KeyCode::Enter, _) => KeyAction::Send,
        (KeyCode::Char('?'), KeyModifiers::NONE) => {
            if input.is_empty() {
                KeyAction::Help
            } else {
                input.push('?');
                KeyAction::None
            }
        }
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

/// Number of display rows a set of lines occupies when wrapped to `width`.
fn wrapped_height(lines: &[Line], width: u16) -> u16 {
    let w = width.max(1) as usize;
    let mut rows: usize = 0;
    for l in lines {
        let lw = l.width();
        rows += if lw == 0 { 1 } else { lw.div_ceil(w) };
    }
    rows.max(1) as u16
}

/// One-line real-time privacy/encryption status for the footer bar.
fn privacy_snapshot(engine: &ChatEngine, guard: &GuardSettings) -> String {
    let size = fmt_bytes(engine.memory.disk_bytes());
    let (sessions, messages) = engine
        .memory
        .stats()
        .map(|s| (s.sessions, s.messages))
        .unwrap_or((0, 0));
    let guard_label = if !guard.enabled {
        "off".to_string()
    } else {
        let mode = match &guard.mode {
            GuardMode::Ask => "ask",
            GuardMode::Redact => "auto",
            GuardMode::Block => "block",
        };
        format!("on({mode})")
    };
    format!(
        "▮ privacy · encrypted db {size} · {sessions} sessions · {messages} messages · AES-256 (SQLCipher) · guard {guard_label} · telemetry off"
    )
}

fn fmt_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    let f = n as f64;
    if f >= MB {
        format!("{:.1} MB", f / MB)
    } else if f >= KB {
        format!("{:.1} KB", f / KB)
    } else {
        format!("{n} B")
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
    guard_state: &str,
    help: bool,
    picker: bool,
    model_picker: bool,
    model_entries: &[(String, String)],
    model_filter: &str,
    model_sel: usize,
    effort_picker: bool,
    effort_sel: usize,
    privacy: &str,
    account: Option<&OpenRouterAccount>,
    changes: &[FileChange],
    attachments: &str,
) {
    let area = f.area();
    // Base background for the whole screen.
    f.render_widget(Block::default().style(Style::default().bg(C_BG)), area);

    let main = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(area);

    // Header bar (surface): logo left, session info right.
    let header_cols =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).split(main[0]);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" ◆ ", Style::default().fg(C_ACCENT)),
            Span::styled(
                "enclave",
                Style::default().fg(C_TEXT).add_modifier(Modifier::BOLD),
            ),
        ]))
        .style(surface()),
        header_cols[0],
    );
    let mut header_right = format!(
        "session '{}' · tools {} · guard {} ",
        engine.session.name,
        if tools_enabled { "on" } else { "off" },
        guard_state
    );
    if let Some(acc) = account {
        let s = acc.summary();
        if s != "no account data" {
            header_right = format!(
                "{} · {s} ",
                header_right.trim_end()
            );
        }
    }
    f.render_widget(
        Paragraph::new(header_right)
            .alignment(Alignment::Right)
            .style(Style::default().fg(C_DIM).bg(C_SURFACE)),
        header_cols[1],
    );

    // Chat area, with an optional sessions sidebar (left) and an info panel
    // (right) — opencode-style, shown only when the terminal is wide enough.
    let show_sidebar = area.width >= 70 && !sessions.is_empty();
    let show_info = area.width >= 110;
    let chat_area = if show_sidebar && show_info {
        let cols = Layout::horizontal([
            Constraint::Length(SIDEBAR_WIDTH),
            Constraint::Min(1),
            Constraint::Length(34),
        ])
        .split(main[1]);
        draw_sidebar(f, cols[0], engine, sessions, sel, focus);
        draw_info_panel(
            f,
            cols[2],
            engine,
            tools_enabled,
            guard_state,
            account,
            changes,
            transcript.len(),
        );
        cols[1]
    } else if show_sidebar {
        let cols = Layout::horizontal([
            Constraint::Length(SIDEBAR_WIDTH),
            Constraint::Min(1),
        ])
        .split(main[1]);
        draw_sidebar(f, cols[0], engine, sessions, sel, focus);
        cols[1]
    } else if show_info {
        let cols = Layout::horizontal([
            Constraint::Min(1),
            Constraint::Length(34),
        ])
        .split(main[1]);
        draw_info_panel(
            f,
            cols[1],
            engine,
            tools_enabled,
            guard_state,
            account,
            changes,
            transcript.len(),
        );
        cols[0]
    } else {
        main[1]
    };

    // Transcript: one subtle band per message — no "you"/"assistant" labels,
    // the panel background itself separates the question from the answer.
    struct Card {
        lines: Vec<Line<'static>>,
        bg: Color,
        accent: Color,
    }
    let inner_w = chat_area.width.saturating_sub(2).max(1);
    let mut cards: Vec<Card> = Vec::new();
    for entry in transcript {
        let card = match entry.speaker {
            Speaker::User => Card {
                lines: entry
                    .text
                    .lines()
                    .map(|l| Line::from(Span::styled(l.to_string(), Style::default().fg(C_TEXT))))
                    .collect(),
                bg: C_SURFACE_HI,
                accent: C_ACCENT,
            },
            Speaker::Assistant => {
                let mut ls = markdown::render(&entry.text);
                if entry.text.trim().is_empty() {
                    ls = vec![Line::from(Span::styled(
                        "…",
                        Style::default().fg(C_DIM).add_modifier(Modifier::ITALIC),
                    ))];
                }
                Card {
                    lines: ls,
                    bg: C_SURFACE,
                    accent: C_SURFACE_HI,
                }
            }
            Speaker::System => Card {
                lines: vec![Line::from(Span::styled(
                    entry.text.clone(),
                    Style::default().fg(C_DIM).add_modifier(Modifier::ITALIC),
                ))],
                bg: C_BG,
                accent: C_BG,
            },
            Speaker::Tool => Card {
                lines: entry
                    .text
                    .lines()
                    .map(|l| {
                        // Diff lines get their own colours: + added, - removed.
                        let style = if l.starts_with('+') {
                            Style::default().fg(C_GREEN)
                        } else if l.starts_with('-') {
                            Style::default().fg(C_RED)
                        } else if l.starts_with("@@") || l.starts_with('…') {
                            Style::default().fg(C_DIM)
                        } else {
                            Style::default().fg(C_YELLOW)
                        };
                        Line::from(Span::styled(l.to_string(), style))
                    })
                    .collect(),
                bg: C_BG,
                accent: C_BG,
            },
        };
        cards.push(card);
    }

    // Empty conversation: show the welcome screen with visible commands.
    if cards.is_empty() {
        cards.push(Card {
            lines: welcome_lines(tools_enabled),
            bg: C_BG,
            accent: C_BG,
        });
    }

    // Lay the cards out vertically, honouring the scroll offset (0 = bottom).
    let gap = 1usize;
    let heights: Vec<u16> = cards
        .iter()
        .map(|c| wrapped_height(&c.lines, inner_w))
        .collect();
    let total: usize =
        heights.iter().map(|h| *h as usize).sum::<usize>() + gap * cards.len().saturating_sub(1);
    let view_h = chat_area.height as usize;
    let max_scroll = total.saturating_sub(view_h);
    let start = max_scroll.saturating_sub(scroll as usize);

    let mut y: usize = 0;
    for (card, h) in cards.iter().zip(heights.iter()) {
        let h = *h as usize;
        let card_top = y;
        let card_bottom = y + h;
        y = card_bottom + gap;
        if card_bottom <= start || card_top >= start + view_h {
            continue;
        }
        let skip = start.saturating_sub(card_top) as u16;
        let row = (card_top.max(start) - start) as u16;
        let avail = (chat_area.height).saturating_sub(row) as usize;
        let draw_h = (h - skip as usize).min(avail).max(1) as u16;
        let rect = Rect {
            x: chat_area.x,
            y: chat_area.y + row,
            width: chat_area.width,
            height: draw_h,
        };
        let para = Paragraph::new(card.lines.clone())
            .style(Style::default().bg(card.bg).fg(C_TEXT))
            .block(Block::default().padding(Padding::new(1, 1, 0, 0)))
            .wrap(Wrap { trim: false })
            .scroll((skip, 0));
        f.render_widget(para, rect);
        if card.accent != card.bg {
            accent_bar(f, rect, card.accent);
        }
    }

    // Bottom panel: proposal prompt while confirming, else the message input.
    // No borders — a raised surface with an accent edge.
    match phase {
        Phase::ToolConfirm { calls, idx, .. } => {
            let call = &calls[*idx];
            let args_pretty = serde_json::from_str::<serde_json::Value>(&call.arguments)
                .ok()
                .and_then(|v| serde_json::to_string_pretty(&v).ok())
                .unwrap_or_else(|| call.arguments.clone());
            let body = format!(
                "⚙ {} — tool call {}/{} · nothing runs without your approval\n{}\nrun? [y]es / [n]o / [a]ll / [q]uit",
                call.name,
                idx + 1,
                calls.len(),
                args_pretty
            );
            let warn = Paragraph::new(body)
                .style(Style::default().fg(C_TEXT).bg(C_SURFACE_HI))
                .block(Block::default().padding(Padding::new(2, 1, 0, 0)))
                .wrap(Wrap { trim: false });
            f.render_widget(warn, main[2]);
            accent_bar(f, main[2], C_YELLOW);
        }
        Phase::Confirming { proposals, idx, .. } => {
            let p = &proposals[*idx];
            let body = format!(
                "$ {} — shell proposal {}/{} · nothing runs without your approval\nrun? [y]es / [n]o / [a]ll / [q]uit",
                p.command,
                idx + 1,
                proposals.len()
            );
            let warn = Paragraph::new(body)
                .style(Style::default().fg(C_TEXT).bg(C_SURFACE_HI))
                .block(Block::default().padding(Padding::new(2, 1, 0, 0)))
                .wrap(Wrap { trim: false });
            f.render_widget(warn, main[2]);
            accent_bar(f, main[2], C_YELLOW);
        }
        _ => {
            let renaming = matches!(phase, Phase::Renaming { .. });
            let is_new = matches!(phase, Phase::Renaming { id: None });
            let accent = if renaming { C_YELLOW } else { C_ACCENT };
            let prompt = if renaming { "› " } else { "❯ " };
            let placeholder = if is_new {
                "session name  (empty = 'chat')"
            } else if renaming {
                "new name"
            } else {
                "send a message…  ( /help commands · ? shortcuts )"
            };
            let (shown, body_fg) = if input.is_empty() {
                (format!("{prompt}{placeholder}"), C_DIM)
            } else {
                let mut it = input.splitn(2, '\n');
                let first = it.next().unwrap_or("");
                match it.next() {
                    Some(rest) => (format!("{prompt}{first}\n{rest}"), C_TEXT),
                    None => (format!("{prompt}{first}"), C_TEXT),
                }
            };
            let input_widget = Paragraph::new(shown)
                .style(Style::default().fg(body_fg).bg(C_SURFACE))
                .block(Block::default().padding(Padding::new(1, 1, 0, 0)));
            f.render_widget(input_widget, main[2]);
            accent_bar(f, main[2], accent);
            if focus == Focus::Chat || renaming {
                let (col, row) = input_cursor(input);
                let prefix_cols = if row == 0 {
                    prompt.chars().count() as u16
                } else {
                    0
                };
                let cursor_x = main[2].x + 1 + prefix_cols + col;
                let cursor_y = main[2].y + row;
                if cursor_x < main[2].x + main[2].width.saturating_sub(1)
                    && cursor_y < main[2].y + main[2].height
                {
                    f.set_cursor_position(Position {
                        x: cursor_x,
                        y: cursor_y,
                    });
                }
            }
        }
    }

    // Real-time privacy / encryption status bar.
    f.render_widget(
        Paragraph::new(format!(" {privacy}")).style(Style::default().fg(C_DIM).bg(C_BG)),
        main[3],
    );

    // Footer: model chip left, key chips right (opencode style).
    let status_style = if status.starts_with("error") {
        Style::default().fg(C_RED)
    } else if matches!(
        phase,
        Phase::Confirming { .. } | Phase::ToolConfirm { .. } | Phase::Guard { .. }
    ) {
        Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(C_DIM)
    };
    let shown_status = if phase_matches_streaming(phase) {
        format!("{spinner} {status}")
    } else {
        status.to_string()
    };
    let scroll_note = if scroll > 0 {
        format!(" ↑{scroll} ")
    } else {
        String::new()
    };

    let foot = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main[4]);
    let mut left = vec![
        Span::styled(
            format!(" {} · {} ", engine.provider_name(), engine.model),
            Style::default()
                .fg(C_BG)
                .bg(C_ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {shown_status}{scroll_note}"),
            status_style,
        ),
    ];
    if !attachments.is_empty() {
        left.push(Span::styled(
            format!(" {attachments} "),
            Style::default().fg(C_ACCENT),
        ));
    }
    if focus == Focus::Sidebar {
        left.extend(chip("↑/↓", "select"));
        left.extend(chip("Enter", "open"));
        left.extend(chip("n", "new"));
        left.extend(chip("r", "rename"));
        left.extend(chip("d", "delete"));
        left.extend(chip("Tab", "back"));
    }
    f.render_widget(Paragraph::new(Line::from(left)).style(surface()), foot[0]);

    let mut right = vec![];
    if focus != Focus::Sidebar {
        right.extend(chip("?", "shortcuts"));
        right.extend(chip("Ctrl-S", "sessions"));
        right.extend(chip("Tab", "sidebar"));
        right.extend(chip("Esc", "quit"));
    }
    f.render_widget(
        Paragraph::new(Line::from(right))
            .alignment(Alignment::Right)
            .style(surface()),
        foot[1],
    );

    // Shortcuts overlay on top of everything.
    if help {
        let box_area = overlay_rect(area);
        overlay_bg(f, box_area, C_ACCENT);
        let mut lines = vec![Line::from(Span::styled(
            "shortcuts",
            Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
        ))];
        lines.extend(welcome_lines(tools_enabled));
        lines.push(plain_line(""));
        lines.push(Line::from(Span::styled(
            "  press any key to close",
            Style::default().fg(C_DIM),
        )));
        let overlay = Paragraph::new(lines)
            .block(Block::default().padding(Padding::new(2, 1, 0, 0)))
            .wrap(Wrap { trim: false });
        f.render_widget(overlay, box_area);
    }

    // Session picker overlay (Ctrl+S or /switch) — works at any terminal size.
    if picker {
        let w = 54.min(area.width.saturating_sub(4));
        let h = ((sessions.len() as u16) + 6).min(area.height.saturating_sub(4));
        let box_area = Rect {
            x: area.width.saturating_sub(w) / 2,
            y: area.height.saturating_sub(h) / 2,
            width: w,
            height: h,
        };
        overlay_bg(f, box_area, C_ACCENT);
        let mut lines: Vec<Line> = vec![Line::from(Span::styled(
            "sessions",
            Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
        ))];
        if sessions.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no sessions yet — press n to create one",
                Style::default().fg(C_DIM),
            )));
        } else {
            for (i, s) in sessions.iter().enumerate() {
                let current = s.id == engine.session.id;
                let marker = if i == sel { "› " } else { "  " };
                let bullet = if current { "●" } else { "○" };
                let name: String = s.name.chars().take(26).collect();
                let style = if i == sel {
                    Style::default()
                        .fg(C_BG)
                        .bg(C_ACCENT)
                        .add_modifier(Modifier::BOLD)
                } else if current {
                    Style::default().fg(C_GREEN)
                } else {
                    Style::default().fg(C_TEXT)
                };
                lines.push(Line::from(Span::styled(
                    format!("{marker}{bullet} {name:<26} {} msg", s.message_count),
                    style,
                )));
            }
        }
        lines.push(plain_line(""));
        lines.push(Line::from(
            [
                chip("↑↓", "select"),
                chip("Enter", "open"),
                chip("n", "new"),
                chip("r", "rename"),
                chip("d", "delete"),
                chip("Esc", "close"),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<Span>>(),
        ));
        let overlay = Paragraph::new(lines)
            .block(Block::default().padding(Padding::new(2, 1, 0, 0)))
            .wrap(Wrap { trim: false });
        f.render_widget(overlay, box_area);
    }
    // Model picker overlay (/model with no argument or /models).
    if model_picker {
        let filtered = filter_entries(model_entries, model_filter);
        let w = 72.min(area.width.saturating_sub(4));
        // Reserve the fixed chrome (title, filter, optional credits, chip row)
        // plus two padding rows so the list never spills outside the box.
        let has_credits = account
            .map(|a| a.summary() != "no account data")
            .unwrap_or(false);
        let chrome = 3 + has_credits as u16;
        let max_rows = (area.height.saturating_sub(chrome + 2) as usize).clamp(3, 60);
        let visible = filtered.len().min(max_rows);
        let title = if filtered.is_empty() {
            format!("models — {}", engine.provider_name())
        } else {
            format!(
                "models — {} · {}/{}",
                engine.provider_name(),
                model_sel + 1,
                filtered.len()
            )
        };
        let mut lines: Vec<Line> = vec![Line::from(Span::styled(
            title,
            Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
        ))];
        lines.push(Line::from(vec![
            Span::styled("  filter: ", Style::default().fg(C_DIM)),
            Span::styled(
                model_filter.to_string(),
                Style::default().fg(C_TEXT).add_modifier(Modifier::BOLD),
            ),
            Span::styled("▏", Style::default().fg(C_ACCENT)),
        ]));
        if let Some(acc) = account {
            let s = acc.summary();
            if s != "no account data" {
                lines.push(Line::from(vec![
                    Span::styled("  credits: ", Style::default().fg(C_DIM)),
                    Span::styled(s, Style::default().fg(C_ACCENT)),
                ]));
            }
        }
        let (start, _end) = list_window(filtered.len(), model_sel, visible);
        // One line per model: truncate to the content width instead of wrapping,
        // so the geometry (and therefore scrolling) stays predictable.
        let content_w = w.saturating_sub(3) as usize;
        if filtered.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no model matches — keep typing or Esc",
                Style::default().fg(C_DIM),
            )));
        } else {
            for (row, &i) in filtered[start..visible + start].iter().enumerate() {
                let (id, meta) = &model_entries[i];
                let selected = start + row == model_sel;
                let current = id == &engine.model;
                let marker = if selected { "› " } else { "  " };
                let bullet = if current { "●" } else { "○" };
                let prefix = format!("{marker}{bullet} ");
                let id_cols = 40.min(content_w.saturating_sub(prefix.chars().count() + 1)).max(4);
                let id_trim: String = id.chars().take(id_cols).collect();
                let used = prefix.chars().count() + id_cols + 1;
                let meta_trim: String = meta.chars().take(content_w.saturating_sub(used)).collect();
                let row_style = if selected {
                    Style::default()
                        .fg(C_BG)
                        .bg(C_ACCENT)
                        .add_modifier(Modifier::BOLD)
                } else if current {
                    Style::default().fg(C_GREEN)
                } else {
                    Style::default().fg(C_TEXT)
                };
                let meta_style = if selected {
                    Style::default().fg(C_BG).bg(C_ACCENT)
                } else {
                    Style::default().fg(C_DIM)
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("{prefix}{id_trim:<id_cols$} "), row_style),
                    Span::styled(meta_trim, meta_style),
                ]));
            }
        }
        let mut chips = [
            chip("↑↓/PgUp-PgDn", "move"),
            chip("type", "filter"),
            chip("Enter", "choose"),
            chip("Esc", "close"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<Span>>();
        if filtered.len() > visible {
            chips.push(Span::styled(
                format!(
                    "  {}-{}/{} ↓ scroll",
                    start + 1,
                    start + visible,
                    filtered.len()
                ),
                Style::default().fg(C_YELLOW),
            ));
        }
        lines.push(Line::from(chips));

        let h = (lines.len() as u16 + 2).min(area.height.saturating_sub(1));
        let box_area = Rect {
            x: area.width.saturating_sub(w) / 2,
            y: area.height.saturating_sub(h) / 2,
            width: w,
            height: h,
        };
        overlay_bg(f, box_area, C_ACCENT);
        let overlay = Paragraph::new(lines)
            .block(Block::default().padding(Padding::new(2, 1, 0, 0)));
        f.render_widget(overlay, box_area);
    }
    // Reasoning-effort picker overlay (opened automatically after choosing a
    // model in the picker, or with the /effort command).
    if effort_picker {
        let w = 46.min(area.width.saturating_sub(4));
        let current = engine.reasoning_effort.as_deref().unwrap_or("default");
        let mut lines: Vec<Line> = vec![Line::from(Span::styled(
            format!("reasoning effort — {}", engine.model),
            Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
        ))];
        lines.push(Line::from(Span::styled(
            "  used by models that support it (OpenRouter/OpenAI)",
            Style::default().fg(C_DIM),
        )));
        for (i, (label, desc)) in EFFORT_OPTIONS.iter().enumerate() {
            let selected = i == effort_sel;
            let marker = if selected { "› " } else { "  " };
            let bullet = if *label == current { "●" } else { "○" };
            let row_style = if selected {
                Style::default()
                    .fg(C_BG)
                    .bg(C_ACCENT)
                    .add_modifier(Modifier::BOLD)
            } else if *label == current {
                Style::default().fg(C_GREEN)
            } else {
                Style::default().fg(C_TEXT)
            };
            let desc_style = if selected {
                Style::default().fg(C_BG).bg(C_ACCENT)
            } else {
                Style::default().fg(C_DIM)
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{marker}{bullet} {label:<8}"), row_style),
                Span::styled((*desc).to_string(), desc_style),
            ]));
        }
        lines.push(Line::from(
            [chip("↑↓", "move"), chip("Enter", "choose"), chip("Esc", "close")]
                .into_iter()
                .flatten()
                .collect::<Vec<Span>>(),
        ));
        let h = (lines.len() as u16 + 2).min(area.height.saturating_sub(1));
        let box_area = Rect {
            x: area.width.saturating_sub(w) / 2,
            y: area.height.saturating_sub(h) / 2,
            width: w,
            height: h,
        };
        overlay_bg(f, box_area, C_ACCENT);
        let overlay = Paragraph::new(lines)
            .block(Block::default().padding(Padding::new(2, 1, 0, 0)));
        f.render_widget(overlay, box_area);
    }
    if let Phase::Guard { text, findings } = phase {
        let box_area = overlay_rect(area);
        overlay_bg(f, box_area, C_RED);
        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(Span::styled(
            "⚠ privacy guard · sensitive data detected",
            Style::default().fg(C_RED).add_modifier(Modifier::BOLD),
        )));
        lines.push(plain_line(""));
        lines.push(Line::from(Span::styled(
            "  what will leave this machine if you send:",
            Style::default().fg(C_DIM),
        )));
        for fd in findings {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {:<12}", fd.kind.label()),
                    Style::default().fg(C_YELLOW),
                ),
                Span::styled(fd.text.clone(), Style::default().fg(C_TEXT)),
            ]));
        }
        lines.push(plain_line(""));
        lines.push(Line::from(Span::styled(
            "  message preview:",
            Style::default().fg(C_DIM),
        )));
        for l in text.lines().take(6) {
            lines.push(Line::from(format!("    {l}")));
        }
        if text.lines().count() > 6 {
            lines.push(plain_line("    …"));
        }
        lines.push(plain_line(""));
        lines.push(Line::from(
            [
                chip("s", "send as-is"),
                chip("p", "placeholders"),
                chip("r", "refuse"),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<Span>>(),
        ));
        lines.push(plain_line(""));
        lines.push(Line::from(Span::styled(
            "  placeholders replace every occurrence with [KIND_n], also in history",
            Style::default().fg(C_DIM),
        )));
        lines.push(Line::from(Span::styled(
            "  re-sent on later turns — original text stays encrypted on disk",
            Style::default().fg(C_DIM),
        )));
        let overlay = Paragraph::new(lines)
            .block(Block::default().padding(Padding::new(3, 1, 0, 0)))
            .wrap(Wrap { trim: false });
        f.render_widget(overlay, box_area);
    }
}

/// Fill an overlay rectangle with a raised surface colour and a left accent
/// edge (no borders).
fn overlay_bg(f: &mut Frame, area: Rect, accent: Color) {
    f.render_widget(Clear, area);
    f.render_widget(
        Block::default().style(Style::default().bg(C_SURFACE_HI)),
        area,
    );
    accent_bar(f, area, accent);
}

/// Draw a one-cell vertical accent bar on the left edge of `area`.
fn accent_bar(f: &mut Frame, area: Rect, accent: Color) {
    let bar = Rect {
        x: area.x,
        y: area.y,
        width: 1,
        height: area.height,
    };
    f.render_widget(Block::default().style(Style::default().bg(accent)), bar);
}

/// Apply a change to config.toml (best-effort; failures are non-fatal).
fn persist_settings(update: impl FnOnce(&mut crate::config::Settings)) {
    if let Ok(paths) = crate::config::Paths::resolve() {
        let _ = paths.ensure_dirs();
        if let Ok(mut s) = crate::config::Settings::load(&paths.config_file) {
            update(&mut s);
            let _ = s.save(&paths.config_file);
        }
    }
}

/// Remember the chosen model across launches.
fn persist_model(model: &str) {
    let model = model.to_string();
    persist_settings(move |s| s.default_model = model);
}

/// Remember the reasoning effort across launches (`None` = model default).
fn persist_effort(effort: Option<&str>) {
    let effort = effort.map(str::to_string);
    persist_settings(move |s| s.reasoning_effort = effort);
}

fn plain_line(s: &str) -> Line<'static> {
    Line::from(s.to_string())
}

/// Centered, capped rectangle for the shortcuts overlay.
fn overlay_rect(area: Rect) -> Rect {
    let w = area.width.saturating_sub(4).min(72);
    let h = area.height.saturating_sub(4).min(28);
    Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    }
}

/// One key-cap chip for the footer: highlighted key + dim label.
fn chip(key: &str, label: &str) -> Vec<Span<'static>> {
    vec![
        Span::styled(
            format!(" {key} "),
            Style::default()
                .fg(C_BG)
                .bg(C_SURFACE_HI)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!(" {label} "), Style::default().fg(C_DIM)),
    ]
}

/// Welcome screen shown when the conversation is empty.
fn welcome_lines(tools_enabled: bool) -> Vec<Line<'static>> {
    let plain = |s: &str| Line::from(s.to_string());
    let dim = |s: &str| Line::from(Span::styled(s.to_string(), Style::default().fg(C_DIM)));
    let key = |k: &str, d: &str| {
        Line::from(vec![
            Span::styled(
                format!("  {k:<10}"),
                Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(d.to_string()),
        ])
    };

    let mut v = vec![
        Line::from(Span::styled(
            "◆ ENCLAVE",
            Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
        )),
        dim("  privacy-first AI · encrypted memory · zero telemetry"),
        dim("  privacy guard: sensitive data is detected before sending — send / placeholder / refuse"),
        plain(""),
        Line::from(Span::styled(
            "COMMANDS — type one and press Enter",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        key("/help", "show this help"),
        key("/new", "start a new session (asks for a name)"),
        key("/switch", "open the session picker (also Ctrl-S)"),
        key("/clear", "wipe the current session"),
        key("/model", "pick a model from the list (saved for next launches)"),
        key("/effort", "reasoning effort (a picker opens right after /model)"),
        key("/attach", "attach an image or text file to your next message"),
        key("/detach", "clear pending attachments"),
        key("/credits", "show OpenRouter credit / usage / limits"),
        key("/quit", "leave"),
        plain(""),
        Line::from(Span::styled(
            "KEYS",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        key("Ctrl-S", "session picker: new · rename · delete · open"),
        key("Tab", "sessions sidebar (↑/↓ select · Enter open · r rename · d delete)"),
        key("Alt+Enter", "newline in the message box"),
        key("Ctrl-L", "clear the current session"),
        key("PgUp/PgDn", "scroll history (mouse wheel works too)"),
        key("Esc", "quit"),
        plain(""),
    ];
    if tools_enabled {
        v.push(dim("  the assistant may propose shell commands: each one asks [y/n] first"));
    } else {
        v.push(dim("  tools disabled: no shell proposals will be offered"));
    }
    v
}

fn phase_matches_streaming(phase: &Phase) -> bool {
    matches!(phase, Phase::Streaming)
}

/// Render the right-hand info panel (opencode-style).
#[allow(clippy::too_many_arguments)]
fn draw_info_panel(
    f: &mut Frame,
    area: Rect,
    engine: &ChatEngine,
    tools_enabled: bool,
    guard_state: &str,
    account: Option<&OpenRouterAccount>,
    changes: &[FileChange],
    transcript_len: usize,
) {
    let (sessions, messages) = engine
        .memory
        .stats()
        .map(|s| (s.sessions, s.messages))
        .unwrap_or((0, 0));
    let id: String = engine.session.id.chars().take(8).collect();
    let est_tokens: usize = engine
        .session
        .messages
        .iter()
        .map(|m| m.content.chars().count())
        .sum::<usize>()
        / 4;

    let label = |k: &str| Span::styled(format!("{k:<9}"), Style::default().fg(C_DIM));
    let mut lines: Vec<Line> = vec![Line::from(Span::styled(
        "info",
        Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
    ))];
    lines.push(Line::from(vec![
        label("session"),
        Span::styled(
            engine.session.name.clone(),
            Style::default().fg(C_TEXT).add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(vec![label("id"), Span::raw(id)]));
    lines.push(Line::from(vec![
        label("model"),
        Span::styled(engine.model.clone(), Style::default().fg(C_ACCENT)),
    ]));
    lines.push(Line::from(vec![
        label("effort"),
        Span::raw(
            engine
                .reasoning_effort
                .clone()
                .unwrap_or_else(|| "default".into()),
        ),
    ]));
    lines.push(Line::from(vec![
        label("provider"),
        Span::raw(engine.provider_name().to_string()),
    ]));
    lines.push(Line::from(vec![
        label("context"),
        Span::raw(format!("~{est_tokens} tok · {transcript_len} lines")),
    ]));
    if let Some(acc) = account {
        let s = acc.summary();
        if s != "no account data" {
            lines.push(Line::from(vec![
                label("credits"),
                Span::styled(s, Style::default().fg(C_ACCENT)),
            ]));
        }
    }
    lines.push(Line::from(vec![
        label("tools"),
        Span::raw(if tools_enabled { "on" } else { "off" }),
    ]));
    lines.push(Line::from(vec![label("guard"), Span::raw(guard_state.to_string())]));
    lines.push(plain_line(""));
    lines.push(Line::from(Span::styled(
        "STORAGE",
        Style::default().fg(C_DIM).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(vec![
        label("db"),
        Span::raw(format!("{} · SQLCipher", fmt_bytes(engine.memory.disk_bytes()))),
    ]));
    lines.push(Line::from(vec![
        label("data"),
        Span::raw(format!("{messages} msg · {sessions} sessions")),
    ]));
    lines.push(plain_line(""));
    lines.push(Line::from(Span::styled(
        "CHANGES",
        Style::default().fg(C_DIM).add_modifier(Modifier::BOLD),
    )));
    if changes.is_empty() {
        lines.push(Line::from(Span::styled(
            "no changes yet",
            Style::default().fg(C_DIM),
        )));
    } else {
        for c in changes.iter().rev().take(12) {
            lines.push(Line::from(vec![
                Span::styled(format!("+{} ", c.added), Style::default().fg(C_GREEN)),
                Span::styled(format!("−{} ", c.removed), Style::default().fg(C_RED)),
                Span::styled(c.path.clone(), Style::default().fg(C_TEXT)),
            ]));
        }
    }

    let panel = Paragraph::new(lines)
        .style(Style::default().bg(C_SURFACE))
        .block(Block::default().padding(Padding::new(2, 1, 0, 0)))
        .wrap(Wrap { trim: false });
    f.render_widget(panel, area);
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
    let mut lines: Vec<Line> = vec![Line::from(Span::styled(
        if focus == Focus::Sidebar {
            "sessions ◆"
        } else {
            "sessions"
        },
        Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
    ))];
    if sessions.is_empty() {
        lines.push(Line::from(Span::styled(
            "no sessions",
            Style::default().fg(C_DIM),
        )));
    }
    for (i, s) in sessions.iter().enumerate() {
        let marker = if s.id == engine.session.id { "●" } else { "○" };
        let name: String = s.name.chars().take(18).collect();
        let style = if i == sel {
            Style::default()
                .fg(C_TEXT)
                .bg(C_SURFACE_HI)
                .add_modifier(Modifier::BOLD)
        } else if s.id == engine.session.id {
            Style::default().fg(C_TEXT)
        } else {
            Style::default().fg(C_DIM)
        };
        lines.push(Line::from(Span::styled(
            format!("{marker} {name} ({})", s.message_count),
            style,
        )));
    }
    let list = Paragraph::new(lines)
        .style(Style::default().bg(C_SURFACE))
        .block(Block::default().padding(Padding::new(1, 1, 0, 0)))
        .wrap(Wrap { trim: false });
    f.render_widget(list, area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_entries_is_case_insensitive_and_matches_meta() {
        let entries = vec![
            ("mistralai/mistral-large-4-0".to_string(), "131k ctx".to_string()),
            ("google/gemma-4-31b-it:free".to_string(), "FREE".to_string()),
            ("openai/gpt-4o".to_string(), "128k ctx".to_string()),
        ];
        assert_eq!(filter_entries(&entries, "").len(), 3);
        assert_eq!(filter_entries(&entries, "MISTRAL"), vec![0]);
        assert_eq!(filter_entries(&entries, "free"), vec![1]);
        assert_eq!(filter_entries(&entries, "gpt"), vec![2]);
        assert!(filter_entries(&entries, "zzz").is_empty());
    }

    #[test]
    fn list_window_keeps_selection_visible() {
        // Everything fits: whole list, no scrolling.
        assert_eq!(list_window(5, 4, 10), (0, 5));
        // Selection centred in a long list.
        assert_eq!(list_window(100, 50, 10), (45, 55));
        // At the top and bottom the window clamps to the list bounds…
        assert_eq!(list_window(100, 0, 10), (0, 10));
        assert_eq!(list_window(100, 99, 10), (90, 100));
        // …and the selection is always inside [start, end).
        for sel in 0..100 {
            let (start, end) = list_window(100, sel, 10);
            assert!(start <= sel && sel < end, "sel {sel} not in {start}..{end}");
            assert!(end - start <= 10);
        }
        // Degenerate sizes must not panic.
        assert_eq!(list_window(0, 0, 10), (0, 0));
        assert_eq!(list_window(100, 50, 0), (0, 0));
    }

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
    fn welcome_screen_lists_commands_and_tools_note() {
        let v = welcome_lines(true);
        let text: String = v.iter().map(|l| l.to_string()).collect();
        assert!(text.contains("/help"));
        assert!(text.contains("/model"));
        assert!(text.contains("/switch"));
        assert!(text.contains("propose shell commands"));
        let v_off = welcome_lines(false);
        let text_off: String = v_off.iter().map(|l| l.to_string()).collect();
        assert!(text_off.contains("tools disabled"));
    }

    #[test]
    fn question_mark_opens_help_when_input_empty() {
        use crossterm::event::{KeyCode, KeyModifiers};
        let q = KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE);
        assert!(matches!(handle_key(q, &mut String::new()), KeyAction::Help));
        let mut typed = String::from("why");
        assert!(matches!(handle_key(q, &mut typed), KeyAction::None));
        assert_eq!(typed, "why?");
    }

    #[test]
    fn ctrl_s_opens_session_picker_and_tab_toggles_sidebar() {
        use crossterm::event::{KeyCode, KeyModifiers};
        let ctrl_s = KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL);
        assert!(matches!(
            handle_key(ctrl_s, &mut String::new()),
            KeyAction::SessionPicker
        ));
        let tab = KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE);
        assert!(matches!(
            handle_key(tab, &mut String::new()),
            KeyAction::ToggleSidebar
        ));
    }

    #[test]
    fn renaming_phase_distinguishes_new_from_existing() {
        let new_session = Phase::Renaming { id: None };
        let existing = Phase::Renaming {
            id: Some("abc".into()),
        };
        assert!(matches!(new_session, Phase::Renaming { id: None }));
        assert!(matches!(existing, Phase::Renaming { id: Some(_) }));
    }

    #[test]
    fn overlay_rect_is_centered_and_capped() {
        use ratatui::layout::Rect;
        let r = overlay_rect(Rect {
            x: 0,
            y: 0,
            width: 100,
            height: 40,
        });
        assert_eq!(r.width, 72);
        assert_eq!(r.height, 28);
        assert_eq!(r.x, 14);
        assert_eq!(r.y, 6);
        let tiny = overlay_rect(Rect {
            x: 0,
            y: 0,
            width: 10,
            height: 6,
        });
        assert_eq!(tiny.width, 6);
        assert_eq!(tiny.height, 2);
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
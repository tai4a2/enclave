//! Full-screen terminal UI built on ratatui (opencode-style layout).

use std::io::{Stdout, stdout};
use std::path::Path;
use std::time::Duration;

use crossterm::event::{
    DisableFocusChange, DisableMouseCapture, EnableFocusChange, EnableMouseCapture, Event,
    EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind,
};
use crossterm::cursor::SetCursorStyle;
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

use crate::config::{Action, GuardMode, GuardSettings, ToolsSettings};
use crate::core::engine::{AgentMode, AgentStep, ApprovedGate, ChatEngine};
use crate::core::attachment::Attachment;
use crate::core::message::{Role, ToolCall};
use crate::core::builtin_tools::FileChange;
use crate::core::tools::{self, Proposal};
use crate::error::Result;
use crate::privacy::SessionInfo;
use crate::privacy::guard::{self, Finding, Redactor};
use crate::privacy::SecureCredentials;
use crate::providers::{ChunkStream, OpenRouterAccount, OpenRouterModel};
use crate::tui::markdown;
use crate::tui::theme::Palette;
use crate::tui::keybinds::{BindAction, Keybinds};

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
/// Active colour palette (read at every draw, switchable at runtime via `/theme`).
static PALETTE: std::sync::RwLock<Palette> =
    std::sync::RwLock::new(crate::tui::theme::DEFAULT);

/// The active palette (defaults to the built-in theme).
fn pal() -> Palette {
    *PALETTE.read().unwrap_or_else(|e| e.into_inner())
}

/// Install a palette (startup config or the `/theme` command).
fn set_palette(palette: Palette) {
    *PALETTE.write().unwrap_or_else(|e| e.into_inner()) = palette;
}

/// Active key-binding overrides (set once at startup from `[tui.keybinds]`).
static KEYBINDS: std::sync::OnceLock<Keybinds> = std::sync::OnceLock::new();

/// The active key bindings (defaults to none — built-in keys apply).
fn keybinds() -> &'static Keybinds {
    KEYBINDS.get_or_init(Keybinds::default)
}

/// Install the key bindings selected in the config (first call wins).
fn set_keybinds(bindings: Keybinds) {
    let _ = KEYBINDS.set(bindings);
}

/// Whether desktop notifications / the terminal bell are enabled (`[tui] notify`).
static NOTIFY_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Seconds after which an Enclave copy auto-clears the clipboard (`[security]`).
static CLIPBOARD_TTL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(30);

fn set_notify(enabled: bool) {
    NOTIFY_ENABLED.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

fn set_clipboard_ttl(secs: u64) {
    CLIPBOARD_TTL.store(secs, std::sync::atomic::Ordering::Relaxed);
}

fn clip_ttl() -> u64 {
    CLIPBOARD_TTL.load(std::sync::atomic::Ordering::Relaxed)
}

/// Best-effort attention signal: terminal bell plus, on macOS, a desktop
/// notification. Never fails the app.
fn notify(summary: &str) {
    let _ = (summary,);
    if !NOTIFY_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    use std::io::Write;
    let mut out = std::io::stdout();
    let _ = out.write_all(b"\x07");
    let _ = out.flush();
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "display notification \"{}\" with title \"Enclave\"",
            summary.replace('"', "'")
        );
        let _ = std::process::Command::new("osascript")
            .arg("-e")
            .arg(script)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
}

/// Full-row surface style used for header/footer bars.
fn surface() -> Style {
    Style::default().bg(pal().surface)
}

/// Text shown by `/help`.
const SLASH_HELP: &str =
    "commands: /help · /new · /switch · /branch [name] [--from N] · /log · /graph · /checkout <name> · /diff <a> <b> · /merge <branch> · /blame <text> · /provenance · /clear · /undo · /redo · /retry · /compact · /find <text> · /search <text> · /model [id] · /effort · /connect [provider] · /thinking · /details · /plan · /build · /attach <path> · /detach · /export [md|html|pdf] [path] · /editor · /init · /mcp · /ledger · /rag [index <paths>|search <q>|status|clear] · /airgap [on|off] · /route [on|off] · /remember <text> · /memory [search <q>|pin <id>] · /forget <id|text> · /checkpoint · /decide <title> [:: why] · /decisions [query] · /exposure · /context · /theme [name] · /commands · /credits · /panic · /quit   (Ctrl-P palette · Ctrl-S picker · Ctrl-R search sessions · Ctrl-Y copy · Ctrl-O editor · Shift+Tab plan/build · @file refs · !shell)";

/// Command palette entries (Ctrl-P): (command, one-line description).
const PALETTE_COMMANDS: &[(&str, &str)] = &[
    ("/help", "show all commands"),
    ("/new", "start a new session"),
    ("/switch", "open the session picker"),
    ("/branch", "fork this conversation into a new branch"),
    ("/log", "show the conversation branch tree"),
    ("/checkout", "switch to a branch by name"),
    ("/diff", "compare two sessions (branch diff)"),
    ("/merge", "merge a branch's new turns into this one"),
    ("/graph", "navigable branch graph (Enter to open)"),
    ("/blame", "locate which turn/branch introduced some text"),
    ("/provenance", "what left the machine for this session (ledger)"),
    ("/clear", "wipe the current session history"),
    ("/model", "pick a model (saved for next launches)"),
    ("/models", "alias of /model"),
    ("/effort", "pick the reasoning effort"),
    ("/connect", "switch provider / add a key"),
    ("/provider", "alias of /connect"),
    ("/thinking", "toggle reasoning detail blocks"),
    ("/details", "toggle tool detail blocks"),
    ("/theme", "pick a colour theme"),
    ("/plan", "switch to read-only Plan mode"),
    ("/build", "switch to Build mode"),
    ("/undo", "remove the last turn"),
    ("/redo", "restore the last undone turn"),
    ("/retry", "re-send the last message"),
    ("/compact", "summarise and shrink the session"),
    ("/find", "search inside this conversation (Ctrl-F)"),
    ("/search", "search across all sessions (Ctrl-R)"),
    ("/export", "export the chat as md/html/pdf"),
    ("/attach", "attach a file or image to the next message"),
    ("/detach", "drop all pending attachments"),
    ("/editor", "edit the message box in $EDITOR (Ctrl-O)"),
    ("/init", "generate an AGENTS.md for this project"),
    ("/rag", "local file index (index/search/status/clear)"),
    ("/ledger", "show the encrypted egress ledger"),
    ("/airgap", "toggle air-gap (local only)"),
    ("/route", "toggle routing of sensitive turns to Ollama"),
    ("/remember", "save a fact to encrypted memory"),
    ("/memory", "list / search / pin memories"),
    ("/forget", "delete a memory"),
    ("/checkpoint", "summarise this session into memory"),
    ("/decide", "record a decision with its rationale"),
    ("/decisions", "list/search recorded decisions"),
    ("/exposure", "privacy blast-radius + posture score"),
    ("/context", "show what goes into the context this turn"),
    ("/commands", "list custom .md commands"),
    ("/credits", "show OpenRouter credits / usage"),
    ("/mcp", "list tools exposed by MCP servers"),
    ("/panic", "lock now (hide the transcript)"),
    ("/quit", "exit Enclave"),
];

/// One rendered transcript entry.
struct ChatLine {
    speaker: Speaker,
    text: String,
}

/// One row of the flattened conversation-branch tree (graph view).
struct GraphRow {
    id: String,
    label: String,
    is_current: bool,
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
    /// Shift+Tab: toggle Plan/Build mode.
    ToggleMode,
    /// Ctrl+S: open the session picker overlay.
    SessionPicker,
    /// Ctrl+Y: enter copy mode (select transcript lines and yank to clipboard).
    CopyMode,
    /// Ctrl+P: recall the previous input from history.
    HistoryPrev,
    /// Ctrl+N: recall the next input from history.
    HistoryNext,
    /// Clear the whole input box (rebindable).
    ClearInput,
    /// Ctrl+R: search across all stored sessions.
    SessionSearch,
    /// Ctrl+O: edit the input in $EDITOR.
    EditInput,
    /// Ctrl+F: search inside the current conversation.
    Find,
    /// Ctrl+P: open the command palette.
    Palette,
}

/// Visual line-selection state for copy mode (Ctrl+Y).
struct CopyState {
    /// Plain (raw markdown) transcript lines, one entry per display line.
    lines: Vec<String>,
    /// Cursor line that moves with the arrows.
    sel: usize,
    /// Fixed end of the selection (set when copy mode opens).
    anchor: usize,
}

/// In-transcript text search overlay (live substring match over the chat).
struct FindState {
    query: String,
    sel: usize,
}

/// Cross-session search overlay (searches the encrypted database).
struct SessionSearch {
    query: String,
    hits: Vec<crate::privacy::SearchHit>,
    sel: usize,
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
    // Apply the theme and key bindings from config.toml (best effort).
    let mut cursor_spec: Option<String> = None;
    let mut cursor_blinking = true;
    if let Ok(paths) = crate::config::Paths::resolve() {
        if let Ok(settings) = crate::config::Settings::load(&paths.config_file) {
            if let Some(name) = &settings.tui.theme {
                if let Some(palette) = crate::tui::theme::by_name(name) {
                    set_palette(palette);
                }
            }
            set_keybinds(Keybinds::from_settings(&settings.tui));
            set_notify(settings.tui.notify);
            set_clipboard_ttl(settings.security.clipboard_clear_secs);
            cursor_spec = settings.tui.cursor.clone();
            cursor_blinking = settings.tui.cursor_blinking;
        }
    }
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(
        out,
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableFocusChange
    )?;
    if let Some(spec) = cursor_spec.as_deref() {
        let style = match (spec, cursor_blinking) {
            ("block", true) => SetCursorStyle::BlinkingBlock,
            ("block", false) => SetCursorStyle::SteadyBlock,
            ("underline", true) => SetCursorStyle::BlinkingUnderScore,
            ("underline", false) => SetCursorStyle::SteadyUnderScore,
            ("line", true) => SetCursorStyle::BlinkingBar,
            ("line", false) => SetCursorStyle::SteadyBar,
            _ => SetCursorStyle::DefaultUserShape,
        };
        let _ = execute!(out, style);
    }
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    let result = run_app(&mut engine, tools_cfg, guard_cfg, agent, &mut terminal).await;

    let _ = disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture,
        DisableFocusChange
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
    // Copy-mode selection (Ctrl+Y) and input history (Ctrl-P / Ctrl-N).
    let mut copy: Option<CopyState> = None;
    let mut history: Vec<String> = Vec::new();
    let mut hist_pos: Option<usize> = None;
    let agent_mode = agent;
    let mut agent_iters: usize = 0;
    if engine.mcp.is_none() {
        if let Ok(paths) = crate::config::Paths::resolve() {
            if let Ok(settings) = crate::config::Settings::load(&paths.config_file) {
                let ws = std::env::current_dir().unwrap_or_default();
                let mcp_sandbox = crate::core::tools::Sandbox::new(tools_cfg.sandbox, ws);
                engine.mcp =
                    crate::core::mcp::McpRegistry::connect_all(&settings.mcp, Some(&mcp_sandbox))
                        .map(std::sync::Arc::new);
            }
        }
    }
    let defs = engine.tool_defs(false);
    let ctx = crate::core::builtin_tools::ToolContext {
        workspace: std::env::current_dir().unwrap_or_default(),
        shell_timeout_secs: tools_cfg.timeout_secs,
        max_output_bytes: tools_cfg.max_output_bytes,
        todos: Some(engine.todos.clone()),
        mcp: engine.mcp.clone(),
        ..Default::default()
    };
    // Local custom commands (`.enclave/commands` + `<config>/commands`).
    let config_dir = crate::config::Paths::resolve()
        .map(|p| p.config_dir)
        .unwrap_or_default();
    let custom: Vec<crate::core::commands::CustomCommand> =
        crate::core::commands::load_all(&ctx.workspace, &config_dir);
    // Last message removed by /undo (restored by /redo).
    let mut last_undone: Option<String> = None;
    // Search overlays: local transcript (/find) and cross-session (Ctrl-R).
    let mut find: Option<FindState> = None;
    let mut search: Option<SessionSearch> = None;
    // Command palette (Ctrl-P), theme picker (/theme), provider picker (/connect).
    let mut palette = false;
    let mut palette_sel: usize = 0;
    let mut theme_picker = false;
    let mut theme_sel: usize = 0;
    let mut provider_picker = false;
    let mut provider_sel: usize = 0;
    // Whether tool/output detail lines are shown in the transcript (/details).
    let mut details = true;
    // `@file` fuzzy completion popup: (matches, sel).
    let mut at_files: Vec<String> = Vec::new();
    let mut at_sel: usize = 0;
    // Slash-command autocomplete candidates (derived from the current input).
    let mut slash_matches: Vec<(String, String)> = Vec::new();
    let mut slash_sel: usize = 0;
    let mut graph = false;
    let mut graph_rows: Vec<GraphRow> = Vec::new();
    let mut graph_sel: usize = 0;
    // Full workspace file list for `@` completion (built once at startup).
    let at_all: Vec<String> = {
        let mut files = Vec::new();
        crate::cli::collect_files(&ctx.workspace, &mut files, 0);
        let mut rel: Vec<String> = files
            .into_iter()
            .filter_map(|p| {
                p.strip_prefix(&ctx.workspace)
                    .ok()
                    .map(|r| r.to_string_lossy().to_string())
            })
            .collect();
        rel.sort();
        rel.truncate(5000);
        rel
    };
    // Optional periodic memory checkpoint (opt-in via `[memory] autosave_secs`).
    let autosave_secs = crate::config::Paths::resolve()
        .ok()
        .and_then(|p| crate::config::Settings::load(&p.config_file).ok())
        .map(|s| s.memory.autosave_secs)
        .unwrap_or(0);
    let mut last_autosave = std::time::Instant::now();
    let mut autosave_mark = engine.session.messages.len();
    let mut theme_current = crate::config::Paths::resolve()
        .ok()
        .and_then(|p| crate::config::Settings::load(&p.config_file).ok())
        .and_then(|s| s.tui.theme)
        .unwrap_or_else(|| "default".to_string());
    // A4: auto-lock + focus handling.
    let security = crate::config::Paths::resolve()
        .ok()
        .and_then(|p| crate::config::Settings::load(&p.config_file).ok())
        .map(|s| s.security)
        .unwrap_or_default();
    let db_path = crate::config::Paths::resolve()
        .map(|p| p.db_path)
        .unwrap_or_default();
    let mut locked = false;
    let mut lock_input = String::new();
    let mut last_activity = std::time::Instant::now();
    let mut unfocused = false;

    loop {
        if !locked
            && security.auto_lock_secs > 0
            && matches!(phase, Phase::Idle)
            && last_activity.elapsed() >= std::time::Duration::from_secs(security.auto_lock_secs)
        {
            locked = true;
            lock_input.clear();
        }
        if autosave_secs > 0
            && matches!(phase, Phase::Idle)
            && last_autosave.elapsed() >= std::time::Duration::from_secs(autosave_secs)
            && engine.session.messages.len() > autosave_mark + 1
        {
            let instruction = "Summarise the key facts, decisions, preferences and open questions of this conversation into a short bullet list suitable for long-term memory. Output only the bullets.";
            if let Ok(sum) = engine.summarize(instruction).await {
                let sum = sum.trim();
                if !sum.is_empty() {
                    let _ = engine.memory.add_memory(
                        sum,
                        "autosave",
                        "checkpoint",
                        Some(&engine.session.id),
                        false,
                    );
                    let _ = engine.reload_memories();
                }
            }
            last_autosave = std::time::Instant::now();
            autosave_mark = engine.session.messages.len();
        }
        let guard_state = if !guard_cfg.enabled {
            "off"
        } else {
            match guard_decision {
                GuardDecision::Undecided => "on",
                GuardDecision::Approved => "approved",
                GuardDecision::Redacted => "placeholders",
            }
        };
        // Refresh `@file` completion candidates from the current input.
        if let Some(q) = at_query(&input) {
            at_files = at_all
                .iter()
                .filter(|p| p.to_lowercase().contains(&q.to_lowercase()))
                .take(50)
                .cloned()
                .collect();
            if at_sel >= at_files.len() {
                at_sel = 0;
            }
        } else {
            at_files.clear();
        }
        // Refresh slash-command autocomplete from the current input.
        slash_matches.clear();
        if let Some(rest) = input.strip_prefix('/') {
            if !rest.contains(char::is_whitespace) {
                let q = rest.to_ascii_lowercase();
                for (cmd, desc) in PALETTE_COMMANDS {
                    let name = cmd.trim_start_matches('/').to_ascii_lowercase();
                    if q.is_empty() || name.contains(&q) {
                        slash_matches.push((cmd.to_string(), desc.to_string()));
                    }
                }
                slash_matches.truncate(50);
            }
        }
        if slash_sel >= slash_matches.len() {
            slash_sel = 0;
        }
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
                copy.as_ref(),
                find.as_ref(),
                search.as_ref(),
                locked,
                &lock_input,
                unfocused,
                details,
                palette,
                palette_sel,
                theme_picker,
                theme_sel,
                &theme_current,
                provider_picker,
                provider_sel,
                &at_files,
                at_sel,
                &slash_matches,
                slash_sel,
                graph,
                &graph_rows,
                graph_sel,
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
                        if matches!(phase, Phase::Confirming { .. }) {
                            notify("shell approval needed");
                        } else {
                            notify("reply ready");
                        }
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
                        execute_proposal(engine, &mut transcript, &mut status, p, tools_cfg.timeout_secs, tools_cfg.max_output_bytes, tools_cfg.sandbox).await?;
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
                                execute_proposal(engine, &mut transcript, &mut status, p, tools_cfg.timeout_secs, tools_cfg.max_output_bytes, tools_cfg.sandbox).await?;
                            }
                            if let Phase::Confirming { approve_all, .. } = &mut phase {
                                *approve_all = true;
                            }
                            advance_proposal(&mut phase, &mut status, idx, total);
                        }
                        ProposalAction::Approve => {
                            if let Some(p) = &proposal {
                                execute_proposal(engine, &mut transcript, &mut status, p, tools_cfg.timeout_secs, tools_cfg.max_output_bytes, tools_cfg.sandbox).await?;
                            }
                            advance_proposal(&mut phase, &mut status, idx, total);
                        }
                        ProposalAction::None => {}
                    }
                }
            }
            Phase::ToolConfirm { .. } => {
                let (call, idx, approve_all) = match &phase {
                    Phase::ToolConfirm {
                        calls,
                        idx,
                        approve_all,
                    } => (calls.get(*idx).cloned(), *idx, *approve_all),
                    _ => (None, 0, false),
                };

                if let Some(Ok(Event::Key(key))) = events.next().await {
                    if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                        continue;
                    }
                    let mut advanced = false;
                    let mut approve_rest = false;
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
                            advanced = true;
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') => {
                            if let Some(c) = &call {
                                engine.push_tool_result(&c.id, "[denied by user]")?;
                            }
                            advanced = true;
                        }
                        KeyCode::Char('a') | KeyCode::Char('A') => {
                            if let Some(c) = &call {
                                agentic_approve(engine, &mut transcript, &mut changes, &ctx, c)
                                    .await?;
                            }
                            advanced = true;
                            approve_rest = true;
                        }
                        _ => {}
                    }
                    if advanced {
                        let calls = match &phase {
                            Phase::ToolConfirm { calls, .. } => calls.clone(),
                            _ => Vec::new(),
                        };
                        match process_tool_calls(
                            engine,
                            &mut transcript,
                            &mut changes,
                            &ctx,
                            calls,
                            idx + 1,
                            approve_rest || approve_all,
                        )
                        .await?
                        {
                            Some(p) => {
                                status = "tool call — approve with y/n/a/q".into();
                                phase = p;
                            }
                            None => {
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
                    }
                }
            }
            Phase::Idle => {
                match events.next().await {
                    Some(Ok(Event::Key(key))) => {
                        last_activity = std::time::Instant::now();
                        if locked {
                            if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                                continue;
                            }
                            match (key.code, key.modifiers) {
                                (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Ok(()),
                                (KeyCode::Enter, _) => {
                                    let pw = std::mem::take(&mut lock_input);
                                    let ok = crate::privacy::Vault::new(&config_dir)
                                        .derive_key(&pw, false)
                                        .and_then(|key| {
                                            crate::privacy::EncryptedMemory::open(&db_path, &key)
                                                .map(|_| ())
                                        })
                                        .is_ok();
                                    if ok {
                                        locked = false;
                                        status = "unlocked".into();
                                    } else {
                                        status = "wrong password".into();
                                    }
                                    last_activity = std::time::Instant::now();
                                }
                                (KeyCode::Backspace, _) => {
                                    lock_input.pop();
                                }
                                (KeyCode::Char(c), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                                    lock_input.push(c);
                                }
                                _ => {}
                            }
                            continue;
                        }
                        // Slash-command autocomplete: navigate/complete.
                        if !slash_matches.is_empty()
                            && matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat)
                        {
                            match key.code {
                                KeyCode::Up => {
                                    slash_sel = slash_sel.saturating_sub(1);
                                    continue;
                                }
                                KeyCode::Down => {
                                    slash_sel =
                                        (slash_sel + 1).min(slash_matches.len().saturating_sub(1));
                                    continue;
                                }
                                KeyCode::Esc => {
                                    input.clear();
                                    slash_matches.clear();
                                    continue;
                                }
                                KeyCode::Tab => {
                                    if let Some((cmd, _)) = slash_matches.get(slash_sel) {
                                        input = format!("{cmd} ");
                                    }
                                    slash_matches.clear();
                                    continue;
                                }
                                KeyCode::Enter => {
                                    let sel = slash_matches.get(slash_sel).map(|(c, _)| c.clone());
                                    if let Some(cmd) = sel {
                                        if input.trim() != cmd.trim() {
                                            input = format!("{cmd} ");
                                            slash_matches.clear();
                                            continue;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        // `@file` completion popup: intercept navigation keys.
                        if !at_files.is_empty()
                            && matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat)
                        {
                            match key.code {
                                KeyCode::Up => {
                                    at_sel = at_sel.saturating_sub(1);
                                    continue;
                                }
                                KeyCode::Down => {
                                    at_sel = (at_sel + 1).min(at_files.len().saturating_sub(1));
                                    continue;
                                }
                                KeyCode::Esc => {
                                    at_files.clear();
                                    continue;
                                }
                                KeyCode::Enter | KeyCode::Tab => {
                                    if let Some(sel) = at_files.get(at_sel).cloned() {
                                        if let Some(q) = at_query(&input) {
                                            input = replace_at_token(&input, &q, &sel);
                                        }
                                    }
                                    at_files.clear();
                                    at_sel = 0;
                                    continue;
                                }
                                _ => {}
                            }
                        }
                        if graph {
                            if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                                continue;
                            }
                            match key.code {
                                KeyCode::Up => graph_sel = graph_sel.saturating_sub(1),
                                KeyCode::Down => {
                                    graph_sel =
                                        (graph_sel + 1).min(graph_rows.len().saturating_sub(1))
                                }
                                KeyCode::Home => graph_sel = 0,
                                KeyCode::End => graph_sel = graph_rows.len().saturating_sub(1),
                                KeyCode::Enter => {
                                    if let Some(row) = graph_rows.get(graph_sel) {
                                        let (id, is_cur) = (row.id.clone(), row.is_current);
                                        if !is_cur {
                                            match crate::core::session::Session::load(
                                                &engine.memory,
                                                &id,
                                            ) {
                                                Ok(sess) => {
                                                    engine.session = sess;
                                                    transcript = transcript_from(engine);
                                                    scroll = 0;
                                                    sessions = engine
                                                        .memory
                                                        .list_sessions()
                                                        .unwrap_or_default();
                                                    persist_settings(|s| {
                                                        s.working_session =
                                                            Some(engine.session.id.clone())
                                                    });
                                                    privacy =
                                                        privacy_snapshot(engine, &guard_cfg);
                                                    status = format!(
                                                        "checked out '{}'",
                                                        engine.session.name
                                                    );
                                                }
                                                Err(e) => status = format!("error: {e}"),
                                            }
                                        }
                                    }
                                    graph = false;
                                }
                                KeyCode::Esc | KeyCode::Char('q') => {
                                    graph = false;
                                    status = "ready".into();
                                }
                                KeyCode::Char('c')
                                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                                {
                                    return Ok(());
                                }
                                _ => {}
                            }
                            continue;
                        }
                        if palette {
                            if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                                continue;
                            }
                            match key.code {
                                KeyCode::Up => palette_sel = palette_sel.saturating_sub(1),
                                KeyCode::Down => {
                                    palette_sel =
                                        (palette_sel + 1).min(PALETTE_COMMANDS.len().saturating_sub(1));
                                }
                                KeyCode::Home => palette_sel = 0,
                                KeyCode::End => palette_sel = PALETTE_COMMANDS.len().saturating_sub(1),
                                KeyCode::Enter => {
                                    if let Some((cmd, _)) = PALETTE_COMMANDS.get(palette_sel) {
                                        input = format!("{cmd} ");
                                    }
                                    palette = false;
                                    status = "command palette — edit then Enter to run".into();
                                }
                                KeyCode::Esc => {
                                    palette = false;
                                    status = "ready".into();
                                }
                                KeyCode::Char('c')
                                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                                {
                                    return Ok(());
                                }
                                _ => {}
                            }
                            continue;
                        }
                        if theme_picker {
                            if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                                continue;
                            }
                            let names = crate::tui::theme::names();
                            match key.code {
                                KeyCode::Up => theme_sel = theme_sel.saturating_sub(1),
                                KeyCode::Down => {
                                    theme_sel = (theme_sel + 1).min(names.len().saturating_sub(1));
                                }
                                KeyCode::Enter => {
                                    if let Some(name) = names.get(theme_sel) {
                                        if let Some(p) = crate::tui::theme::by_name(name) {
                                            set_palette(p);
                                            persist_theme(name);
                                            theme_current = (*name).to_string();
                                            status = format!("theme: {name} (saved)");
                                        }
                                    }
                                    theme_picker = false;
                                    privacy = privacy_snapshot(engine, &guard_cfg);
                                }
                                KeyCode::Esc => {
                                    theme_picker = false;
                                    status = "ready".into();
                                }
                                _ => {}
                            }
                            continue;
                        }
                        if provider_picker {
                            if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                                continue;
                            }
                            let names = crate::providers::known_providers();
                            match key.code {
                                KeyCode::Up => provider_sel = provider_sel.saturating_sub(1),
                                KeyCode::Down => {
                                    provider_sel =
                                        (provider_sel + 1).min(names.len().saturating_sub(1));
                                }
                                KeyCode::Enter => {
                                    if let Some(name) = names.get(provider_sel) {
                                        match engine.set_provider(name) {
                                            Ok(()) => {
                                                persist_settings(|s| {
                                                    s.default_provider = (*name).to_string()
                                                });
                                                status = format!(
                                                    "provider: {name} (model {}) — set a key with `enclave keys set {name}` if needed",
                                                    engine.model
                                                );
                                            }
                                            Err(e) => status = format!("error: {e}"),
                                        }
                                    }
                                    provider_picker = false;
                                    privacy = privacy_snapshot(engine, &guard_cfg);
                                }
                                KeyCode::Esc => {
                                    provider_picker = false;
                                    status = "ready".into();
                                }
                                _ => {}
                            }
                            continue;
                        }
                        if copy.is_some() {
                            if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                                continue;
                            }
                            let mut exit: Option<String> = None;
                            {
                                let cs = copy.as_mut().unwrap();
                                let last = cs.lines.len().saturating_sub(1);
                                match (key.code, key.modifiers) {
                                    (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Ok(()),
                                    (KeyCode::Esc, _) | (KeyCode::Char('q'), _) => {
                                        exit = Some("ready".into())
                                    }
                                    (KeyCode::Up, _) | (KeyCode::Char('k'), _) => {
                                        cs.sel = cs.sel.saturating_sub(1)
                                    }
                                    (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
                                        cs.sel = (cs.sel + 1).min(last)
                                    }
                                    (KeyCode::PageUp, _) => cs.sel = cs.sel.saturating_sub(10),
                                    (KeyCode::PageDown, _) => cs.sel = (cs.sel + 10).min(last),
                                    (KeyCode::Home, _) => cs.sel = 0,
                                    (KeyCode::End, _) => cs.sel = last,
                                    (KeyCode::Char('a'), _) => {
                                        cs.anchor = 0;
                                        cs.sel = last;
                                    }
                                    (KeyCode::Char('e'), _) => {
                                        exit = Some(copy_status(&last_reply_text(&transcript)))
                                    }
                                    (KeyCode::Char('y'), _) | (KeyCode::Enter, _) => {
                                        let (a, b) = if cs.anchor <= cs.sel {
                                            (cs.anchor, cs.sel)
                                        } else {
                                            (cs.sel, cs.anchor)
                                        };
                                        let text = if cs.lines.is_empty() {
                                            String::new()
                                        } else {
                                            cs.lines[a..=b].join("\n")
                                        };
                                        exit = Some(copy_status(&text));
                                    }
                                    _ => {}
                                }
                            }
                            if let Some(st) = exit {
                                copy = None;
                                status = st;
                            }
                            continue;
                        }
                        if find.is_some() {
                            if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                                continue;
                            }
                            let lines = transcript_copy_lines(&transcript);
                            let mut exit: Option<String> = None;
                            {
                                let fs = find.as_mut().unwrap();
                                let matches = find_matches(&lines, &fs.query);
                                let last = matches.len().saturating_sub(1);
                                fs.sel = fs.sel.min(last);
                                match (key.code, key.modifiers) {
                                    (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Ok(()),
                                    (KeyCode::Esc, _) => exit = Some("ready".into()),
                                    (KeyCode::Enter, _) => {
                                        if let Some(&idx) = matches.get(fs.sel) {
                                            let t = lines.get(idx).cloned().unwrap_or_default();
                                            exit = Some(copy_status(&t));
                                        } else {
                                            exit = Some("no match to copy".into());
                                        }
                                    }
                                    (KeyCode::Up, _) => fs.sel = fs.sel.saturating_sub(1),
                                    (KeyCode::Down, _) => fs.sel = (fs.sel + 1).min(last),
                                    (KeyCode::PageUp, _) => fs.sel = fs.sel.saturating_sub(10),
                                    (KeyCode::PageDown, _) => fs.sel = (fs.sel + 10).min(last),
                                    (KeyCode::Char('u'), KeyModifiers::CONTROL) => {
                                        fs.query.clear();
                                        fs.sel = 0;
                                    }
                                    (KeyCode::Backspace, _) => {
                                        fs.query.pop();
                                        fs.sel = 0;
                                    }
                                    (KeyCode::Char(ch), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                                        fs.query.push(ch);
                                        fs.sel = 0;
                                    }
                                    _ => {}
                                }
                            }
                            if let Some(st) = exit {
                                find = None;
                                status = st;
                            }
                            continue;
                        }
                        if search.is_some() {
                            if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                                continue;
                            }
                            let mut exit: Option<String> = None;
                            let mut load: Option<String> = None;
                            let mut changed = false;
                            {
                                let ss = search.as_mut().unwrap();
                                let last = ss.hits.len().saturating_sub(1);
                                ss.sel = ss.sel.min(last);
                                match (key.code, key.modifiers) {
                                    (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Ok(()),
                                    (KeyCode::Esc, _) => exit = Some("ready".into()),
                                    (KeyCode::Enter, _) => {
                                        if let Some(h) = ss.hits.get(ss.sel) {
                                            load = Some(h.session_id.clone());
                                        }
                                    }
                                    (KeyCode::Up, _) => ss.sel = ss.sel.saturating_sub(1),
                                    (KeyCode::Down, _) => ss.sel = (ss.sel + 1).min(last),
                                    (KeyCode::PageUp, _) => ss.sel = ss.sel.saturating_sub(10),
                                    (KeyCode::PageDown, _) => ss.sel = (ss.sel + 10).min(last),
                                    (KeyCode::Char('u'), KeyModifiers::CONTROL) => {
                                        ss.query.clear();
                                        ss.sel = 0;
                                        changed = true;
                                    }
                                    (KeyCode::Backspace, _) => {
                                        ss.query.pop();
                                        ss.sel = 0;
                                        changed = true;
                                    }
                                    (KeyCode::Char(ch), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                                        ss.query.push(ch);
                                        ss.sel = 0;
                                        changed = true;
                                    }
                                    _ => {}
                                }
                                if changed {
                                    refresh_session_search(engine, ss);
                                }
                            }
                            if let Some(id) = load {
                                search = None;
                                if id == engine.session.id {
                                    status = "already on this session".into();
                                } else if let Ok(sess) =
                                    crate::core::session::Session::load(&engine.memory, &id)
                                {
                                    engine.session = sess;
                                    transcript = transcript_from(engine);
                                    scroll = 0;
                                    sessions = engine.memory.list_sessions().unwrap_or_default();
                                    persist_settings(|s| {
                                        s.working_session = Some(engine.session.id.clone())
                                    });
                                    status = "opened session from search".into();
                                } else {
                                    status = "could not open session".into();
                                }
                                continue;
                            }
                            if let Some(st) = exit {
                                search = None;
                                status = st;
                            }
                            continue;
                        }
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
                            KeyAction::ClearInput => input.clear(),
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
                            KeyAction::SessionSearch => {
                                search = Some(SessionSearch {
                                    query: String::new(),
                                    hits: Vec::new(),
                                    sel: 0,
                                });
                                status =
                                    "session search — type to search, ↑/↓ select, Enter open, Esc close"
                                        .into();
                            }
                            KeyAction::EditInput => match edit_in_editor(terminal, &input) {
                                Ok(new) => {
                                    input = new;
                                    status = "input loaded from editor".into();
                                }
                                Err(e) => status = format!("editor failed: {e}"),
                            },
                            KeyAction::Find => {
                                find = Some(FindState {
                                    query: String::new(),
                                    sel: 0,
                                });
                                status =
                                    "find — type to search this conversation, Enter copies the line, Esc close"
                                        .into();
                            }
                            KeyAction::CopyMode => {
                                let lines = transcript_copy_lines(&transcript);
                                if lines.is_empty() {
                                    status = "nothing to copy yet".into();
                                } else {
                                    let last = lines.len() - 1;
                                    copy = Some(CopyState {
                                        lines,
                                        sel: last,
                                        anchor: last,
                                    });
                                    status = "copy — ↑/↓ select · y copy · a all · e last reply · Esc cancel".into();
                                }
                            }
                            KeyAction::HistoryPrev => {
                                if !history.is_empty() {
                                    let pos = match hist_pos {
                                        None => history.len() - 1,
                                        Some(0) => 0,
                                        Some(p) => p - 1,
                                    };
                                    hist_pos = Some(pos);
                                    input = history[pos].clone();
                                }
                            }
                            KeyAction::HistoryNext => match hist_pos {
                                Some(p) if p + 1 < history.len() => {
                                    let np = p + 1;
                                    hist_pos = Some(np);
                                    input = history[np].clone();
                                }
                                Some(_) => {
                                    hist_pos = None;
                                    input.clear();
                                }
                                None => {}
                            },
                            KeyAction::ToggleMode => {
                                engine.mode = match engine.mode {
                                    AgentMode::Build => AgentMode::Plan,
                                    AgentMode::Plan => AgentMode::Build,
                                };
                                status = format!(
                                    "mode: {} — {}",
                                    engine.mode.label(),
                                    if engine.mode.is_plan() {
                                        "read-only (edits & shell refused)"
                                    } else {
                                        "full access (per permission policy)"
                                    }
                                );
                                privacy = privacy_snapshot(engine, &guard_cfg);
                            }
                            KeyAction::Palette => {
                                palette = true;
                                palette_sel = 0;
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
                                    "switch" | "sessions" | "resume" | "continue" => {
                                        sessions =
                                            engine.memory.list_sessions().unwrap_or_default();
                                        picker = true;
                                        status = "session picker — ↑/↓ select, Enter open, n new, r rename, d delete, Esc close".into();
                                    }
                                    "branch" => {
                                        let mut keep = engine.session.messages.len();
                                        let mut name = String::new();
                                        let mut toks = arg.split_whitespace();
                                        while let Some(tok) = toks.next() {
                                            if tok == "--from" {
                                                if let Some(n) = toks.next() {
                                                    keep = n.parse().unwrap_or(keep);
                                                }
                                            } else if let Some(n) = tok.strip_prefix("--from=") {
                                                keep = n.parse().unwrap_or(keep);
                                            } else {
                                                name = tok.to_string();
                                            }
                                        }
                                        keep = keep.min(engine.session.messages.len());
                                        let name = if name.is_empty() {
                                            let base = engine.session.name.clone();
                                            let n = engine
                                                .memory
                                                .branch_nodes()
                                                .map(|ns| {
                                                    ns.iter()
                                                        .filter(|x| {
                                                            x.name
                                                                .starts_with(&format!("{base}~"))
                                                        })
                                                        .count()
                                                        + 1
                                                })
                                                .unwrap_or(1);
                                            format!("{base}~{n}")
                                        } else {
                                            name
                                        };
                                        match crate::core::session::Session::fork(
                                            &engine.memory,
                                            &engine.session.id,
                                            &name,
                                            keep,
                                        ) {
                                            Ok(sess) => {
                                                engine.session = sess;
                                                transcript = transcript_from(engine);
                                                scroll = 0;
                                                sessions = engine
                                                    .memory
                                                    .list_sessions()
                                                    .unwrap_or_default();
                                                sel = 0;
                                                persist_settings(|s| {
                                                    s.working_session =
                                                        Some(engine.session.id.clone())
                                                });
                                                privacy = privacy_snapshot(engine, &guard_cfg);
                                                status = format!(
                                                    "branched to '{name}' ({} messages copied) — parent untouched",
                                                    engine.session.messages.len()
                                                );
                                            }
                                            Err(e) => status = format!("error: {e}"),
                                        }
                                    }
                                    "checkout" => {
                                        let target = arg.trim();
                                        if target.is_empty() {
                                            status = "usage: /checkout <session name or id>".into();
                                        } else {
                                            let nodes =
                                                engine.memory.branch_nodes().unwrap_or_default();
                                            let found = nodes.iter().find(|n| {
                                                n.id == target
                                                    || n.name == target
                                                    || n.id.starts_with(target)
                                            });
                                            match found
                                                .map(|n| n.id.clone())
                                                .map(|id| {
                                                    crate::core::session::Session::load(
                                                        &engine.memory,
                                                        &id,
                                                    )
                                                }) {
                                                Some(Ok(sess)) => {
                                                    engine.session = sess;
                                                    transcript = transcript_from(engine);
                                                    scroll = 0;
                                                    sessions = engine
                                                        .memory
                                                        .list_sessions()
                                                        .unwrap_or_default();
                                                    persist_settings(|s| {
                                                        s.working_session =
                                                            Some(engine.session.id.clone())
                                                    });
                                                    privacy =
                                                        privacy_snapshot(engine, &guard_cfg);
                                                    status = format!(
                                                        "checked out '{}'",
                                                        engine.session.name
                                                    );
                                                }
                                                Some(Err(e)) => status = format!("error: {e}"),
                                                None => status =
                                                    format!("no session matches '{target}'"),
                                            }
                                        }
                                    }
                                    "log" => {
                                        let nodes =
                                            engine.memory.branch_nodes().unwrap_or_default();
                                        let text =
                                            branch_tree_text(&nodes, &engine.session.id);
                                        transcript.push(ChatLine {
                                            speaker: Speaker::System,
                                            text,
                                        });
                                        scroll = 0;
                                        status = "conversation branch tree".into();
                                    }
                                    "diff" => {
                                        let mut parts = arg.split_whitespace();
                                        let a = parts.next().map(str::to_string);
                                        let b = parts.next().map(str::to_string);
                                        match (a, b) {
                                            (Some(a), Some(b)) => {
                                                let nodes = engine
                                                    .memory
                                                    .branch_nodes()
                                                    .unwrap_or_default();
                                                let resolve = |q: &str| {
                                                    nodes
                                                        .iter()
                                                        .find(|n| {
                                                            n.id == q
                                                                || n.name == q
                                                                || n.id.starts_with(q)
                                                        })
                                                        .map(|n| n.id.clone())
                                                };
                                                match (resolve(&a), resolve(&b)) {
                                                    (Some(ia), Some(ib)) => {
                                                        let ta = session_text(
                                                            &engine.memory, &ia,
                                                        );
                                                        let tb = session_text(
                                                            &engine.memory, &ib,
                                                        );
                                                        let d = crate::core::diff::lines(&ta, &tb);
                                                        let (added, removed) =
                                                            crate::core::diff::stats(&d);
                                                        let body = crate::core::diff::render(
                                                            &d, 200,
                                                        );
                                                        transcript.push(ChatLine {
                                                            speaker: Speaker::System,
                                                            text: format!(
                                                                "diff {a} → {b}   (+{added} −{removed})\n{body}"
                                                            ),
                                                        });
                                                        scroll = 0;
                                                        status = format!(
                                                            "diff +{added} −{removed}"
                                                        );
                                                    }
                                                    _ => status =
                                                        "one or both sessions not found"
                                                            .into(),
                                                }
                                            }
                                            _ => status =
                                                "usage: /diff <session a> <session b>".into(),
                                        }
                                    }
                                    "merge" => {
                                        let target = arg.trim();
                                        if target.is_empty() {
                                            status = "usage: /merge <branch name or id>".into();
                                        } else {
                                            let nodes =
                                                engine.memory.branch_nodes().unwrap_or_default();
                                            let found = nodes
                                                .iter()
                                                .find(|n| {
                                                    n.id == target
                                                        || n.name == target
                                                        || n.id.starts_with(target)
                                                })
                                                .map(|n| (n.id.clone(), n.name.clone()));
                                            match found {
                                                Some((id, _)) if id == engine.session.id => {
                                                    status =
                                                        "cannot merge a branch into itself".into();
                                                }
                                                Some((id, name)) => {
                                                    match engine
                                                        .session
                                                        .merge_from(&engine.memory, &id)
                                                    {
                                                        Ok(0) => status = format!(
                                                            "'{name}' has nothing new to merge"
                                                        ),
                                                        Ok(n) => {
                                                            transcript =
                                                                transcript_from(engine);
                                                            scroll = 0;
                                                            sessions = engine
                                                                .memory
                                                                .list_sessions()
                                                                .unwrap_or_default();
                                                            privacy = privacy_snapshot(
                                                                engine, &guard_cfg,
                                                            );
                                                            status = format!(
                                                                "merged '{name}' (+{n} messages)"
                                                            );
                                                        }
                                                        Err(e) => {
                                                            status = format!("error: {e}")
                                                        }
                                                    }
                                                }
                                                None => status =
                                                    format!("no branch matches '{target}'"),
                                            }
                                        }
                                    }
                                    "graph" | "tree" => {
                                        let nodes =
                                            engine.memory.branch_nodes().unwrap_or_default();
                                        let mut snippets: std::collections::HashMap<
                                            String,
                                            String,
                                        > = std::collections::HashMap::new();
                                        for node in &nodes {
                                            if let Ok(hist) =
                                                engine.memory.get_history(&node.id, 100_000)
                                            {
                                                if let Some(first) = hist
                                                    .iter()
                                                    .find(|m| m.role == Role::User)
                                                    .or_else(|| hist.first())
                                                {
                                                    let snip: String = first
                                                        .content
                                                        .lines()
                                                        .next()
                                                        .unwrap_or("")
                                                        .chars()
                                                        .take(48)
                                                        .collect();
                                                    if !snip.is_empty() {
                                                        snippets.insert(node.id.clone(), snip);
                                                    }
                                                }
                                            }
                                        }
                                        graph_rows =
                                            flatten_tree(&nodes, &engine.session.id, &snippets);
                                        graph_sel = graph_rows
                                            .iter()
                                            .position(|r| r.is_current)
                                            .unwrap_or(0);
                                        graph = true;
                                        status =
                                            "branch graph — ↑/↓ select, Enter open, Esc close"
                                                .into();
                                    }
                                    "blame" => {
                                        let q = arg.trim();
                                        if q.is_empty() {
                                            status = "usage: /blame <text to locate>".into();
                                        } else {
                                            let needle = q.to_ascii_lowercase();
                                            let hits: Vec<String> = engine
                                                .session
                                                .messages
                                                .iter()
                                                .enumerate()
                                                .filter(|(_, m)| {
                                                    m.content.to_ascii_lowercase().contains(&needle)
                                                })
                                                .map(|(i, m)| {
                                                    let first = m
                                                        .content
                                                        .lines()
                                                        .next()
                                                        .unwrap_or("")
                                                        .chars()
                                                        .take(80)
                                                        .collect::<String>();
                                                    format!(
                                                        "  #{:<3} {:<9} {}",
                                                        i + 1,
                                                        m.role.as_str(),
                                                        first
                                                    )
                                                })
                                                .collect();
                                            let mut text =
                                                format!("blame '{q}': {} match(es)\n", hits.len());
                                            if hits.is_empty() {
                                                text.push_str(
                                                    "  (not found in this session's messages)",
                                                );
                                            } else {
                                                let nodes = engine
                                                    .memory
                                                    .branch_nodes()
                                                    .unwrap_or_default();
                                                if let Some(node) = nodes
                                                    .iter()
                                                    .find(|n| n.id == engine.session.id)
                                                {
                                                    if let Some(pid) = &node.parent {
                                                        let inherited = session_text(
                                                            &engine.memory, pid,
                                                        )
                                                        .to_ascii_lowercase()
                                                        .contains(&needle);
                                                        text.push_str(if inherited {
                                                            "  lineage: present in the parent branch (inherited)\n"
                                                        } else {
                                                            "  lineage: introduced in THIS branch\n"
                                                        });
                                                    }
                                                }
                                                text.push_str(&hits.join("\n"));
                                            }
                                            transcript.push(ChatLine {
                                                speaker: Speaker::System,
                                                text,
                                            });
                                            scroll = 0;
                                            status = format!("blame: {} match(es)", hits.len());
                                        }
                                    }
                                    "provenance" | "egress" => {
                                        match engine
                                            .memory
                                            .list_egress_for_session(&engine.session.id, 50)
                                        {
                                            Ok(entries) => {
                                                let mut text = if entries.is_empty() {
                                                    "provenance · no egress recorded for this session yet"
                                                        .to_string()
                                                } else {
                                                    format!(
                                                        "provenance · {} send(s) from this session\n",
                                                        entries.len()
                                                    )
                                                };
                                                for e in entries.iter().rev() {
                                                    let red = if e.redactions.is_empty() {
                                                        String::new()
                                                    } else {
                                                        format!("  [redacted: {}]", e.redactions)
                                                    };
                                                    let orig = if e.original_sha.is_empty() {
                                                        String::new()
                                                    } else {
                                                        format!(
                                                            "  commit {}",
                                                            &e.original_sha[..12.min(e.original_sha.len())]
                                                        )
                                                    };
                                                    text.push_str(&format!(
                                                        "  #{} {} {}-{}  {} B  sha {}{}{}\n",
                                                        e.id,
                                                        e.ts,
                                                        e.provider,
                                                        e.model,
                                                        e.payload_bytes,
                                                        &e.payload_sha[..12.min(e.payload_sha.len())],
                                                        red,
                                                        orig
                                                    ));
                                                }
                                                transcript.push(ChatLine {
                                                    speaker: Speaker::System,
                                                    text,
                                                });
                                                scroll = 0;
                                                status =
                                                    "provenance (egress ledger for this session)"
                                                        .into();
                                            }
                                            Err(e) => status = format!("error: {e}"),
                                        }
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
                                    "copy" => {
                                        let n: usize =
                                            arg.trim().parse().unwrap_or(1).clamp(1, 99);
                                        let mut picked: Vec<&str> = transcript
                                            .iter()
                                            .filter(|c| {
                                                c.speaker == Speaker::Assistant
                                                    && !c.text.trim().is_empty()
                                            })
                                            .map(|c| c.text.as_str())
                                            .rev()
                                            .take(n)
                                            .collect();
                                        picked.reverse();
                                        if picked.is_empty() {
                                            status = "no assistant replies to copy yet".into();
                                        } else {
                                            status = copy_status(&picked.join("\n\n"));
                                        }
                                    }
                                    "save" => {
                                        let path = if arg.trim().is_empty() {
                                            let short = &engine.session.id
                                                [..8.min(engine.session.id.len())];
                                            format!("enclave-{short}.md")
                                        } else {
                                            arg.trim().to_string()
                                        };
                                        let md = session_markdown(engine, &transcript);
                                        let n = md.chars().count();
                                        match std::fs::write(&path, md) {
                                            Ok(()) => {
                                                status = format!(
                                                    "saved {n} chars to {path} (plaintext — not encrypted)"
                                                )
                                            }
                                            Err(e) => status = format!("save failed: {e}"),
                                        }
                                    }
                                    "plan" => {
                                        engine.mode = AgentMode::Plan;
                                        status =
                                            "mode: plan — read-only (edits & shell refused)".into();
                                        privacy = privacy_snapshot(engine, &guard_cfg);
                                    }
                                    "build" => {
                                        engine.mode = AgentMode::Build;
                                        status = "mode: build — full access (per permission policy)"
                                            .into();
                                        privacy = privacy_snapshot(engine, &guard_cfg);
                                    }
                                    "undo" => match engine.undo_last_turn() {
                                        Ok(Some(text)) => {
                                            last_undone = Some(text.clone());
                                            input = text;
                                            transcript = transcript_from(engine);
                                            scroll = 0;
                                            sessions =
                                                engine.memory.list_sessions().unwrap_or_default();
                                            privacy = privacy_snapshot(engine, &guard_cfg);
                                            status =
                                                "undone — edit and press Enter, or /redo to restore".into();
                                        }
                                        Ok(None) => status = "nothing to undo".into(),
                                        Err(e) => status = format!("error: {e}"),
                                    },
                                    "redo" => match &last_undone {
                                        Some(text) => {
                                            input = text.clone();
                                            status = "restored — press Enter to send".into();
                                        }
                                        None => status = "nothing to redo".into(),
                                    },
                                    "retry" => match engine.undo_last_turn() {
                                        Ok(Some(text)) => {
                                            transcript = transcript_from(engine);
                                            scroll = 0;
                                            sessions =
                                                engine.memory.list_sessions().unwrap_or_default();
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
                                                    Vec::new(),
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
                                                    Vec::new(),
                                                )
                                                .await?;
                                            }
                                        }
                                        Ok(None) => status = "nothing to retry".into(),
                                        Err(e) => status = format!("error: {e}"),
                                    },
                                    "compact" | "summarize" => {
                                        match engine.compact().await {
                                            Ok(summary) => {
                                                transcript = transcript_from(engine);
                                                scroll = 0;
                                                privacy = privacy_snapshot(engine, &guard_cfg);
                                                status = format!(
                                                    "compacted — history replaced with a {} char summary",
                                                    summary.chars().count()
                                                );
                                            }
                                            Err(e) => status = format!("error: {e}"),
                                        }
                                    }
                                    "commands" => {
                                        if custom.is_empty() {
                                            status =
                                                "no custom commands (add .md files to .enclave/commands or <config>/commands)".into();
                                        } else {
                                            let list = custom
                                                .iter()
                                                .map(|c| {
                                                    if c.description.is_empty() {
                                                        format!("/{}", c.name)
                                                    } else {
                                                        format!("/{} — {}", c.name, c.description)
                                                    }
                                                })
                                                .collect::<Vec<_>>()
                                                .join("\n");
                                            transcript.push(ChatLine {
                                                speaker: Speaker::System,
                                                text: format!("custom commands:\n{list}"),
                                            });
                                            status =
                                                format!("{} custom command(s)", custom.len());
                                        }
                                    }
                                    "theme" | "themes" => {
                                        let all = crate::tui::theme::names().join(", ");
                                        let want = arg.trim();
                                        if want.is_empty() {
                                            let names = crate::tui::theme::names();
                                            theme_sel = names
                                                .iter()
                                                .position(|n| *n == theme_current)
                                                .unwrap_or(0);
                                            theme_picker = true;
                                            status = format!(
                                                "theme picker — ↑/↓ select, Enter choose, Esc close (current: {theme_current})"
                                            );
                                        } else if let Some(p) =
                                            crate::tui::theme::by_name(want)
                                        {
                                            set_palette(p);
                                            persist_theme(want);
                                            status =
                                                format!("theme: {want} (saved for next launches)");
                                        } else {
                                            status = format!(
                                                "unknown theme '{want}' (available: {all})"
                                            );
                                        }
                                    }
                                    "find" => {
                                        let q = arg.trim().to_string();
                                        let n = find_matches(
                                            &transcript_copy_lines(&transcript),
                                            &q,
                                        )
                                        .len();
                                        find = Some(FindState { query: q, sel: 0 });
                                        status = format!(
                                            "find: {n} match(es) — type to refine, Enter copies, Esc closes"
                                        );
                                    }
                                    "search" | "search-all" => {
                                        let mut ss = SessionSearch {
                                            query: arg.trim().to_string(),
                                            hits: Vec::new(),
                                            sel: 0,
                                        };
                                        refresh_session_search(engine, &mut ss);
                                        let n = ss.hits.len();
                                        search = Some(ss);
                                        status = format!(
                                            "session search: {n} hit(s) — type to refine, Enter opens, Esc closes"
                                        );
                                    }
                                    "export" => {
                                        let mut it = arg.split_whitespace();
                                        let fmt = it.next().unwrap_or("html");
                                        let path = it.next();
                                        match crate::core::export::Format::parse(fmt) {
                                            Some(f) => {
                                                let short =
                                                    &engine.session.id[..8.min(engine.session.id.len())];
                                                let out = path
                                                    .map(std::path::PathBuf::from)
                                                    .unwrap_or_else(|| {
                                                        std::path::PathBuf::from(format!(
                                                            "enclave-{short}.{}",
                                                            f.extension()
                                                        ))
                                                    });
                                                match crate::core::export::export(
                                                    &engine.session.name,
                                                    &engine.model,
                                                    &engine.session.messages,
                                                    f,
                                                    &out,
                                                ) {
                                                    Ok(()) => {
                                                        status = format!(
                                                            "exported to {} (plaintext, not encrypted)",
                                                            out.display()
                                                        )
                                                    }
                                                    Err(e) => {
                                                        status = format!("export failed: {e}")
                                                    }
                                                }
                                            }
                                            None => {
                                                status = "usage: /export [md|html|pdf] [path]".into()
                                            }
                                        }
                                    }
                                    "init" => {
                                        let ws = std::env::current_dir().unwrap_or_default();
                                        let target = ws.join("AGENTS.md");
                                        if target.exists() {
                                            status =
                                                "AGENTS.md already exists — edit it or remove it first"
                                                    .into();
                                        } else {
                                            let context = project_context(&ws);
                                            let prompt = format!(
                                                "You are generating an AGENTS.md file for a software \
                                                 project. From the file listing and key files below, \
                                                 write concise guidance for an AI coding agent: \
                                                 build / test / lint commands, code style, project \
                                                 structure and conventions. Reply with the AGENTS.md \
                                                 content ONLY, in Markdown, without wrapping the whole \
                                                 file in a code fence.\n\n{context}"
                                            );
                                            match engine.one_shot(&prompt).await {
                                                Ok(text) => {
                                                    let body = strip_code_fence(&text);
                                                    match std::fs::write(&target, body) {
                                                        Ok(()) => {
                                                            transcript.push(ChatLine {
                                                                speaker: Speaker::System,
                                                                text: format!(
                                                                    "AGENTS.md created at {}",
                                                                    target.display()
                                                                ),
                                                            });
                                                            status = format!(
                                                                "wrote {}",
                                                                target.display()
                                                            );
                                                        }
                                                        Err(e) => {
                                                            status =
                                                                format!("could not write AGENTS.md: {e}")
                                                        }
                                                    }
                                                }
                                                Err(e) => status = format!("error: {e}"),
                                            }
                                        }
                                    }
                                    "mcp" => {
                                        match engine.mcp.as_ref() {
                                            Some(reg) => {
                                                let names = reg.tool_names();
                                                if names.is_empty() {
                                                    status = "MCP: connected but no tools exposed".into();
                                                } else {
                                                    transcript.push(ChatLine {
                                                        speaker: Speaker::System,
                                                        text: format!(
                                                            "MCP tools ({}):\n{}",
                                                            names.len(),
                                                            names.join("\n")
                                                        ),
                                                    });
                                                    status = format!("{} MCP tool(s) available", names.len());
                                                }
                                            }
                                            None => {
                                                status = "no MCP servers configured (add [mcp.servers.<name>] to config.toml)".into()
                                            }
                                        }
                                    }
                                    "ledger" => {
                                        match engine.memory.verify_egress_chain() {
                                            Ok(ok) => {
                                                let n = engine.memory.egress_count().unwrap_or(0);
                                                let entries =
                                                    engine.memory.list_egress(20).unwrap_or_default();
                                                let mut body = format!(
                                                    "egress ledger · {n} entries · chain {}\n",
                                                    if ok { "OK" } else { "BROKEN — modified" }
                                                );
                                                for e in entries {
                                                    let sha = e.payload_sha.get(..12).unwrap_or(&e.payload_sha);
                                                    let red = if e.redactions.is_empty() {
                                                        String::new()
                                                    } else {
                                                        format!("  [{}]", e.redactions)
                                                    };
                                                    body.push_str(&format!(
                                                        "#{} {} {} · sha {}{}\n",
                                                        e.id, e.provider, e.model, sha, red
                                                    ));
                                                }
                                                body.push_str(
                                                    "fingerprints only — never payloads or secrets",
                                                );
                                                transcript.push(ChatLine {
                                                    speaker: Speaker::System,
                                                    text: body,
                                                });
                                                status =
                                                    format!("egress ledger: {n} entries (chain {})", if ok { "OK" } else { "BROKEN" });
                                            }
                                            Err(e) => status = format!("error: {e}"),
                                        }
                                    }
                                    "rag" => {
                                        let mut parts = arg.trim().splitn(2, char::is_whitespace);
                                        let sub = parts.next().unwrap_or("");
                                        let rest = parts.next().unwrap_or("").trim();
                                        match sub {
                                            "index" => {
                                                let mut files = Vec::new();
                                                for p in rest.split_whitespace() {
                                                    crate::cli::collect_files(
                                                        std::path::Path::new(p),
                                                        &mut files,
                                                        0,
                                                    );
                                                }
                                                let mut total = 0usize;
                                                for file in &files {
                                                    let source = file.display().to_string();
                                                    let Ok(data) = std::fs::read(file) else { continue };
                                                    let Ok(text) = String::from_utf8(data) else { continue };
                                                    if text.trim().is_empty() {
                                                        continue;
                                                    }
                                                    engine.memory.clear_rag_source(&source).ok();
                                                    for (i, chunk) in crate::core::rag::chunk_text(&text, 1200).iter().enumerate() {
                                                        engine.memory.add_rag_chunk(&source, i as i64, chunk, None).ok();
                                                        total += 1;
                                                    }
                                                }
                                                let n = engine.memory.rag_count().unwrap_or(0);
                                                status = format!("indexed {} file(s), {total} chunk(s) — {n} total", files.len());
                                            }
                                            "search" => {
                                                let chunks = engine.memory.all_rag_chunks().unwrap_or_default();
                                                let readable: Vec<crate::privacy::RagChunk> = chunks
                                                    .into_iter()
                                                    .filter(|c| crate::core::rag::is_readable(std::path::Path::new(&c.source)))
                                                    .collect();
                                                let hits = crate::core::rag::keyword_search(rest, &readable, 5);
                                                if hits.is_empty() {
                                                    status = "no indexed chunks matched".to_string();
                                                } else {
                                                    let mut body = format!("rag search · {} hit(s)\n", hits.len());
                                                    for (i, h) in hits.iter().enumerate() {
                                                        body.push_str(&format!("\n[{}/{}] {} ({:.2})\n{}\n", i + 1, hits.len(), h.source, h.score, h.text));
                                                    }
                                                    transcript.push(ChatLine { speaker: Speaker::System, text: body });
                                                    status = format!("{} hit(s)", hits.len());
                                                }
                                            }
                                            "status" => {
                                                let sources = engine.memory.rag_sources().unwrap_or_default();
                                                if sources.is_empty() {
                                                    status = "RAG index is empty".to_string();
                                                } else {
                                                    let mut body = String::from("rag index\n");
                                                    for (src, n) in &sources {
                                                        body.push_str(&format!("{n:>5}  {src}\n"));
                                                    }
                                                    transcript.push(ChatLine { speaker: Speaker::System, text: body });
                                                    status = format!("{} source(s), {} chunk(s)", sources.len(), engine.memory.rag_count().unwrap_or(0));
                                                }
                                            }
                                            "clear" => {
                                                let n = engine.memory.clear_rag().unwrap_or(0);
                                                status = format!("cleared {n} chunk(s)");
                                            }
                                            _ => status = "usage: /rag index <paths> | /rag search <query> | /rag status | /rag clear".to_string(),
                                        }
                                    }
                                    "airgap" | "air-gap" => {
                                        engine.air_gap = match arg.trim() {
                                            "on" | "true" | "1" => true,
                                            "off" | "false" | "0" => false,
                                            _ => !engine.air_gap,
                                        };
                                        status = if engine.air_gap {
                                            "air-gap ON — nothing will be sent to remote providers".into()
                                        } else {
                                            "air-gap OFF — remote providers allowed".into()
                                        };
                                    }
                                    "route" | "routing" => {
                                        engine.route_sensitive = match arg.trim() {
                                            "on" | "true" | "1" | "local" => true,
                                            "off" | "false" | "0" | "same" => false,
                                            _ => !engine.route_sensitive,
                                        };
                                        status = if engine.route_sensitive {
                                            "sensitive routing ON — sensitive turns go to local Ollama".into()
                                        } else {
                                            "sensitive routing OFF — all turns use the selected provider".into()
                                        };
                                    }
                                    "remember" => {
                                        let mut words: Vec<String> = Vec::new();
                                        let mut tags: Vec<String> = Vec::new();
                                        let mut local_only = false;
                                        for tok in arg.split_whitespace() {
                                            if tok == "--local" {
                                                local_only = true;
                                            } else if let Some(t) = tok.strip_prefix('#') {
                                                if !t.is_empty() {
                                                    tags.push(t.to_string());
                                                }
                                            } else {
                                                words.push(tok.to_string());
                                            }
                                        }
                                        let text = words.join(" ");
                                        if text.is_empty() {
                                            status =
                                                "usage: /remember <text> [#tags] [--local]".into();
                                        } else {
                                            match engine.memory.add_memory(
                                                &text,
                                                &tags.join(","),
                                                "note",
                                                Some(&engine.session.id),
                                                local_only,
                                            ) {
                                                Ok(id) => {
                                                    let _ = engine.reload_memories();
                                                    status = format!(
                                                        "remembered [{}]{}",
                                                        &id[..8.min(id.len())],
                                                        if local_only { " (local-only)" } else { "" }
                                                    );
                                                }
                                                Err(e) => status = format!("error: {e}"),
                                            }
                                        }
                                    }
                                    "memory" | "memories" => {
                                        let mut it = arg.split_whitespace();
                                        let sub = it.next().unwrap_or("");
                                        let rest = it.collect::<Vec<_>>().join(" ");
                                        match sub {
                                            "pin" | "unpin" => {
                                                if rest.is_empty() {
                                                    status = "usage: /memory pin <id>".into();
                                                } else {
                                                    match engine
                                                        .memory
                                                        .set_memory_pinned(&rest, sub == "pin")
                                                    {
                                                        Ok(true) => {
                                                            let _ = engine.reload_memories();
                                                            status = format!(
                                                                "{} [{}]",
                                                                if sub == "pin" { "pinned" } else { "unpinned" },
                                                                &rest[..8.min(rest.len())]
                                                            );
                                                        }
                                                        Ok(false) => status =
                                                            format!("no memory with id '{rest}'"),
                                                        Err(e) => status = format!("error: {e}"),
                                                    }
                                                }
                                            }
                                            _ => {
                                                let query = if sub == "search" { rest } else { arg.trim().to_string() };
                                                let res = if query.is_empty() {
                                                    engine.memory.list_memories(50)
                                                } else {
                                                    engine.memory.search_memories(&query, 50)
                                                };
                                                match res {
                                                    Ok(mems) if mems.is_empty() => {
                                                        status = if query.is_empty() {
                                                            "no memories yet (use /remember <text>)".into()
                                                        } else {
                                                            format!("no memory matches '{query}'")
                                                        }
                                                    }
                                                    Ok(mems) => {
                                                        let body = memories_to_text(&mems);
                                                        transcript.push(ChatLine {
                                                            speaker: Speaker::System,
                                                            text: format!(
                                                                "memory ({}):\n{body}",
                                                                mems.len()
                                                            ),
                                                        });
                                                        status = format!("{} memor{}", mems.len(), if mems.len() == 1 { "y" } else { "ies" });
                                                    }
                                                    Err(e) => status = format!("error: {e}"),
                                                }
                                            }
                                        }
                                    }
                                    "forget" => {
                                        let what = arg.trim().to_string();
                                        if what.is_empty() {
                                            status = "usage: /forget <id|text>".into();
                                        } else {
                                            match engine.memory.delete_memory(&what) {
                                                Ok(true) => {
                                                    let _ = engine.reload_memories();
                                                    status = format!("forgot [{}]", &what[..8.min(what.len())]);
                                                }
                                                Ok(false) => match engine
                                                    .memory
                                                    .delete_memories_matching(&what)
                                                {
                                                    Ok(0) => status = format!("no memory matched '{what}'"),
                                                    Ok(n) => {
                                                        let _ = engine.reload_memories();
                                                        status = format!("forgot {n} memor{}", if n == 1 { "y" } else { "ies" });
                                                    }
                                                    Err(e) => status = format!("error: {e}"),
                                                },
                                                Err(e) => status = format!("error: {e}"),
                                            }
                                        }
                                    }
                                    "checkpoint" => match engine
                                        .summarize(
                                            "Summarise the key facts, decisions, preferences and open questions from this conversation into a short bullet list suitable for long-term memory. Reply with the bullet list only.",
                                        )
                                        .await
                                    {
                                        Ok(sum) => {
                                            let sum = sum.trim().to_string();
                                            if sum.is_empty() {
                                                status = "nothing to checkpoint".into();
                                            } else {
                                                match engine.memory.add_memory(
                                                    &sum,
                                                    "checkpoint",
                                                    "checkpoint",
                                                    Some(&engine.session.id),
                                                    false,
                                                ) {
                                                    Ok(_) => {
                                                        let _ = engine.reload_memories();
                                                        transcript.push(ChatLine {
                                                            speaker: Speaker::System,
                                                            text: format!("checkpoint saved to memory:\n{sum}"),
                                                        });
                                                        status = "checkpoint saved to memory".into();
                                                    }
                                                    Err(e) => status = format!("error: {e}"),
                                                }
                                            }
                                        }
                                        Err(e) => status = format!("error: {e}"),
                                    },
                                    "decide" => {
                                        let raw = arg.trim();
                                        if raw.is_empty() {
                                            status = "usage: /decide <title> [:: rationale]".into();
                                        } else {
                                            let (title, body) = match raw.split_once("::") {
                                                Some((t, b)) => (t.trim().to_string(), b.trim().to_string()),
                                                None => (raw.to_string(), String::new()),
                                            };
                                            match engine.memory.add_decision(
                                                Some(&engine.session.id),
                                                &title,
                                                &body,
                                                "",
                                                "accepted",
                                            ) {
                                                Ok(id) => {
                                                    let _ = engine.reload_decisions();
                                                    transcript.push(ChatLine {
                                                        speaker: Speaker::System,
                                                        text: format!(
                                                            "decision recorded [{}] {}",
                                                            &id[..8.min(id.len())],
                                                            title
                                                        ),
                                                    });
                                                    status = "decision recorded".into();
                                                }
                                                Err(e) => status = format!("error: {e}"),
                                            }
                                        }
                                    }
                                    "decisions" => {
                                        let q = arg.trim();
                                        let res = if q.is_empty() {
                                            engine.memory.list_decisions(50)
                                        } else {
                                            engine.memory.search_decisions(q, 50)
                                        };
                                        match res {
                                            Ok(ds) if ds.is_empty() => {
                                                status = if q.is_empty() {
                                                    "no decisions yet (use /decide <title> :: <why>)".into()
                                                } else {
                                                    format!("no decision matches '{q}'")
                                                }
                                            }
                                            Ok(ds) => {
                                                let body = decisions_to_text(&ds);
                                                transcript.push(ChatLine {
                                                    speaker: Speaker::System,
                                                    text: format!("decisions ({}):\n{body}", ds.len()),
                                                });
                                                status = format!("{} decision(s)", ds.len());
                                            }
                                            Err(e) => status = format!("error: {e}"),
                                        }
                                    }
                                    "exposure" | "blast-radius" => match exposure_text(engine, &guard_cfg, &tools_cfg) {
                                        Ok(t) => {
                                            transcript.push(ChatLine {
                                                speaker: Speaker::System,
                                                text: t,
                                            });
                                            status = "privacy blast-radius".into();
                                        }
                                        Err(e) => status = format!("error: {e}"),
                                    },
                                    "context" => {
                                        transcript.push(ChatLine {
                                            speaker: Speaker::System,
                                            text: context_text(engine),
                                        });
                                        status = "context inspects what is sent".into();
                                    }
                                    "panic" => {
                                        locked = true;
                                        lock_input.clear();
                                        transcript.clear();
                                        scroll = 0;
                                        status = "panic — locked (enter your master password to resume)".into();
                                    }
                                    "palette" => {
                                        palette = true;
                                        palette_sel = 0;
                                    }
                                    "connect" | "provider" | "providers" => {
                                        let names = crate::providers::known_providers();
                                        provider_sel = names
                                            .iter()
                                            .position(|n| *n == engine.provider_name())
                                            .unwrap_or(0);
                                        provider_picker = true;
                                        status = "provider picker — ↑/↓ select, Enter switch, Esc close".into();
                                    }
                                    "details" | "thinking" => {
                                        details = !details;
                                        status = format!(
                                            "details: {}",
                                            if details { "shown" } else { "hidden" }
                                        );
                                    }
                                    "quit" | "exit" | "q" => return Ok(()),
                                    "" => status = "type /help for the command list".into(),
                                    other => {
                                        if let Some(c) =
                                            crate::core::commands::find(&custom, other)
                                        {
                                            let expanded =
                                                crate::core::commands::expand(&c.template, &arg);
                                            input = expanded;
                                            status = format!(
                                                "command /{other} expanded — review and press Enter"
                                            );
                                        } else {
                                            status = format!(
                                                "unknown command '/{other}' — try /help"
                                            );
                                        }
                                    }
                                }
                                continue;
                            }

                            // `!command`: run locally and show the output. It is
                            // never sent to the provider.
                            if let Some(cmd) = text.strip_prefix('!') {
                                let cmd = cmd.trim().to_string();
                                if cmd.is_empty() {
                                    status = "usage: !<shell command>".into();
                                } else {
                                    transcript.push(ChatLine {
                                        speaker: Speaker::User,
                                        text: format!("!{cmd}"),
                                    });
                                    match tools::run_sandboxed(
                                        &cmd,
                                        Duration::from_secs(tools_cfg.timeout_secs),
                                        tools_cfg.max_output_bytes,
                                        Some(&tools::Sandbox::new(
                                            tools_cfg.sandbox,
                                            std::env::current_dir().unwrap_or_default(),
                                        )),
                                    )
                                    .await
                                    {
                                        Ok(out) => {
                                            for line in out.render().lines() {
                                                transcript.push(ChatLine {
                                                    speaker: Speaker::Tool,
                                                    text: line.to_string(),
                                                });
                                            }
                                            scroll = 0;
                                            status =
                                                "command finished — output kept local".into();
                                        }
                                        Err(e) => status = format!("error: {e}"),
                                    }
                                }
                                continue;
                            }

                            // Resolve `@path` references into attachments.
                            let refs =
                                crate::core::commands::resolve_file_refs(&text, &ctx.workspace);
                            if !refs.names.is_empty() {
                                status = format!("attached: {}", refs.names.join(", "));
                                pending.extend(refs.attachments);
                            }
                            let text = refs.text;

                            history.push(text.clone());
                            hist_pos = None;

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
                    Some(Ok(Event::FocusLost)) => {
                        unfocused = true;
                    }
                    Some(Ok(Event::FocusGained)) => {
                        unfocused = false;
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
                                            persist_settings(|st| {
                                                st.working_session =
                                                    Some(engine.session.id.clone())
                                            });
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

/// The current `@file` completion query (text after a trailing `@` token).
fn at_query(input: &str) -> Option<String> {
    let token = input.rsplit(|c: char| c.is_whitespace()).next().unwrap_or("");
    token.strip_prefix('@').map(|q| q.to_string())
}

/// Replace a trailing `@<query>` token with `@<sel> `.
fn replace_at_token(input: &str, query: &str, sel: &str) -> String {
    let old = format!("@{query}");
    if let Some(pos) = input.rfind(&old) {
        if pos + old.len() == input.len() {
            let mut s = input[..pos].to_string();
            s.push('@');
            s.push_str(sel);
            s.push(' ');
            return s;
        }
    }
    input.to_string()
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
            persist_settings(|s| s.working_session = Some(engine.session.id.clone()));
            *status = format!("opened session '{}'", info.name);
        }
        Err(e) => *status = format!("error: {e}"),
    }
    Ok(())
}

/// Rebuild the transcript from the engine's current session messages.
fn transcript_from(engine: &ChatEngine) -> Vec<ChatLine> {
    engine
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
        .collect()
}

/// ASCII tree of the conversation branches (strongly-connected by lineage).
fn branch_tree_text(nodes: &[crate::privacy::BranchNode], current: &str) -> String {
    use std::collections::{BTreeMap, HashSet};
    let ids: HashSet<&str> = nodes.iter().map(|n| n.id.as_str()).collect();
    let mut children: BTreeMap<Option<String>, Vec<&crate::privacy::BranchNode>> = BTreeMap::new();
    for node in nodes {
        let parent = node.parent.clone().filter(|p| ids.contains(p.as_str()));
        children.entry(parent).or_default().push(node);
    }
    fn walk(
        children: &BTreeMap<Option<String>, Vec<&crate::privacy::BranchNode>>,
        parent: Option<String>,
        prefix: &str,
        current: &str,
        out: &mut String,
    ) {
        if let Some(list) = children.get(&parent) {
            let total = list.len();
            for (i, node) in list.iter().enumerate() {
                let last = i + 1 == total;
                let connector = if last { "└─ " } else { "├─ " };
                let marker = if node.id == current { "●" } else { "○" };
                let from = if node.parent.is_some() && node.from >= 0 {
                    format!(" ← @{}", node.from)
                } else {
                    String::new()
                };
                out.push_str(&format!(
                    "{prefix}{connector}{marker} {}  ({} msg){from}\n",
                    node.name, node.message_count
                ));
                let next_prefix = format!("{prefix}{}", if last { "   " } else { "│  " });
                walk(children, Some(node.id.clone()), &next_prefix, current, out);
            }
        }
    }
    let mut out = String::from("conversation branch tree:\n");
    walk(&children, None, "", current, &mut out);
    if nodes.is_empty() {
        out.push_str("(no sessions)");
    }
    out
}

/// Flatten a stored session into plain text for diffing.
fn session_text(memory: &crate::privacy::EncryptedMemory, id: &str) -> String {
    memory
        .get_history(id, 100_000)
        .unwrap_or_default()
        .iter()
        .map(|m| format!("{}: {}", m.role.as_str(), m.content))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Flatten the branch tree into navigable rows (depth-prefixed labels).
fn flatten_tree(
    nodes: &[crate::privacy::BranchNode],
    current: &str,
    snippets: &std::collections::HashMap<String, String>,
) -> Vec<GraphRow> {
    use std::collections::{BTreeMap, HashSet};
    let ids: HashSet<&str> = nodes.iter().map(|n| n.id.as_str()).collect();
    let mut children: BTreeMap<Option<String>, Vec<&crate::privacy::BranchNode>> = BTreeMap::new();
    for node in nodes {
        let parent = node.parent.clone().filter(|p| ids.contains(p.as_str()));
        children.entry(parent).or_default().push(node);
    }
    fn walk(
        children: &BTreeMap<Option<String>, Vec<&crate::privacy::BranchNode>>,
        parent: Option<String>,
        prefix: &str,
        current: &str,
        snippets: &std::collections::HashMap<String, String>,
        rows: &mut Vec<GraphRow>,
    ) {
        if let Some(list) = children.get(&parent) {
            let total = list.len();
            for (i, node) in list.iter().enumerate() {
                let last = i + 1 == total;
                let connector = if last { "└─ " } else { "├─ " };
                let marker = if node.id == current { "●" } else { "○" };
                let from = if node.parent.is_some() && node.from >= 0 {
                    format!("  ← @{}", node.from)
                } else {
                    String::new()
                };
                let snippet = snippets.get(&node.id).cloned().unwrap_or_default();
                let snip_part = if snippet.is_empty() {
                    String::new()
                } else {
                    format!("  · {snippet}")
                };
                rows.push(GraphRow {
                    id: node.id.clone(),
                    label: format!(
                        "{prefix}{connector}{marker} {}  ({} msg){from}{snip_part}",
                        node.name, node.message_count
                    ),
                    is_current: node.id == current,
                });
                let next_prefix = format!("{prefix}{}", if last { "   " } else { "│  " });
                walk(
                    children,
                    Some(node.id.clone()),
                    &next_prefix,
                    current,
                    snippets,
                    rows,
                );
            }
        }
    }
    let mut rows = Vec::new();
    walk(&children, None, "", current, snippets, &mut rows);
    rows
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
    changes: &mut Vec<FileChange>,
    agent_iters: &mut usize,
    defs: &[crate::providers::ToolDef],
    ctx: &crate::core::builtin_tools::ToolContext,
) -> Result<()> {
    loop {
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
                notify("reply ready");
                return Ok(());
            }
            Ok(AgentStep::ToolCalls { text, calls }) => {
                if !text.trim().is_empty() {
                    transcript.push(ChatLine {
                        speaker: Speaker::Assistant,
                        text,
                    });
                }
                match process_tool_calls(engine, transcript, changes, ctx, calls, 0, false).await? {
                    Some(p) => {
                        *status = "tool call — approve with y/n/a/q".into();
                        *phase = p;
                        notify("tool approval needed");
                        return Ok(());
                    }
                    None => continue,
                }
            }
            Err(e) => {
                *status = format!("error: {e}");
                *phase = Phase::Idle;
                return Ok(());
            }
        }
    }
}

/// Auto-run calls the permission policy allows, auto-deny the denied ones and
/// stop at the first that needs confirmation. Returns the confirm phase, or
/// `None` when every call was handled.
async fn process_tool_calls(
    engine: &mut ChatEngine,
    transcript: &mut Vec<ChatLine>,
    changes: &mut Vec<FileChange>,
    ctx: &crate::core::builtin_tools::ToolContext,
    calls: Vec<ToolCall>,
    mut idx: usize,
    approve_all: bool,
) -> Result<Option<Phase>> {
    while idx < calls.len() {
        let call = calls[idx].clone();
        let action = if approve_all {
            Action::Allow
        } else {
            engine.effective_action(&call)
        };
        match action {
            Action::Deny => {
                transcript.push(ChatLine {
                    speaker: Speaker::Tool,
                    text: format!("\u{26d4} {} [denied by policy]", call.name),
                });
                engine.push_tool_result(&call.id, "[denied by policy]")?;
                idx += 1;
            }
            Action::Allow => {
                agentic_approve(engine, transcript, changes, ctx, &call).await?;
                idx += 1;
            }
            Action::Ask => {
                return Ok(Some(Phase::ToolConfirm {
                    calls,
                    idx,
                    approve_all,
                }));
            }
        }
    }
    Ok(None)
}

/// Execute one approved tool call, render its output and persist the result.
async fn agentic_approve(
    engine: &mut ChatEngine,
    transcript: &mut Vec<ChatLine>,
    changes: &mut Vec<FileChange>,
    ctx: &crate::core::builtin_tools::ToolContext,
    call: &ToolCall,
) -> Result<()> {
    if let Some(res) = engine.execute_stateful(call) {
        let text = match res {
            Ok(t) => t,
            Err(e) => format!("[tool error] {e}"),
        };
        for line in text.lines() {
            transcript.push(ChatLine {
                speaker: Speaker::Tool,
                text: line.to_string(),
            });
        }
        engine.push_tool_result(&call.id, &text)?;
        return Ok(());
    }
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
    sandbox: crate::config::SandboxMode,
) -> Result<()> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let sandbox = tools::Sandbox::new(sandbox, std::env::current_dir().unwrap_or_default());
    match tools::run_sandboxed(&p.command, timeout, max_output_bytes, Some(&sandbox)).await {
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
    // User-configured overrides win over the built-in bindings.
    if let Some(action) = keybinds().action_for(&key) {
        return match action {
            BindAction::Quit => KeyAction::Quit,
            BindAction::Clear => KeyAction::Clear,
            BindAction::CopyMode => KeyAction::CopyMode,
            BindAction::SessionPicker => KeyAction::SessionPicker,
            BindAction::ToggleSidebar => KeyAction::ToggleSidebar,
            BindAction::ToggleMode => KeyAction::ToggleMode,
            BindAction::Newline => KeyAction::Newline,
            BindAction::HistoryPrev => KeyAction::HistoryPrev,
            BindAction::HistoryNext => KeyAction::HistoryNext,
            BindAction::DeleteWord => KeyAction::DeleteWord,
            BindAction::ClearInput => KeyAction::ClearInput,
            BindAction::Send => KeyAction::Send,
            BindAction::SessionSearch => KeyAction::SessionSearch,
            BindAction::EditInput => KeyAction::EditInput,
        };
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
        (KeyCode::Char('r'), KeyModifiers::CONTROL) => KeyAction::SessionSearch,
        (KeyCode::Char('o'), KeyModifiers::CONTROL) => KeyAction::EditInput,
        (KeyCode::Char('f'), KeyModifiers::CONTROL) => KeyAction::Find,
        (KeyCode::Char('y'), KeyModifiers::CONTROL) => KeyAction::CopyMode,
        (KeyCode::Char('p'), KeyModifiers::CONTROL) => KeyAction::Palette,
        (KeyCode::Char('n'), KeyModifiers::CONTROL) => KeyAction::HistoryNext,
        (KeyCode::Char('p'), KeyModifiers::ALT) => KeyAction::HistoryPrev,
        (KeyCode::Tab, _) => KeyAction::ToggleSidebar,
        (KeyCode::BackTab, _) => KeyAction::ToggleMode,
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

/// Copy `text` to the system clipboard and return a short status message.
/// Gather a compact view of the workspace (file listing + key files) for `/init`.
fn project_context(workspace: &std::path::Path) -> String {
    let mut s = String::new();
    s.push_str("Project files (relative paths):\n");
    for p in crate::core::builtin_tools::list_files(workspace).iter().take(200) {
        if let Ok(rel) = p.strip_prefix(workspace) {
            s.push_str(&format!("- {}\n", rel.display()));
        }
    }
    let key_files = [
        "README.md",
        "readme.md",
        "Cargo.toml",
        "package.json",
        "pyproject.toml",
        "go.mod",
        "Makefile",
        "requirements.txt",
    ];
    for name in key_files {
        let p = workspace.join(name);
        if let Ok(content) = std::fs::read_to_string(&p) {
            let trimmed: String = content.chars().take(4000).collect();
            s.push_str(&format!("\n=== {name} ===\n{trimmed}\n"));
        }
    }
    s
}

/// Strip a surrounding ``` fence (with optional language tag) from model output.
fn strip_code_fence(text: &str) -> String {
    let t = text.trim();
    if let Some(rest) = t.strip_prefix("```") {
        let rest = rest.split_once('\n').map(|x| x.1).unwrap_or("");
        let rest = rest.trim_end();
        let rest = rest.strip_suffix("```").unwrap_or(rest);
        return rest.trim_end().to_string();
    }
    t.to_string()
}

fn copy_status(text: &str) -> String {
    if text.is_empty() {
        return "nothing to copy".to_string();
    }
    match crate::clipboard::copy_with_ttl(text, clip_ttl()) {
        Ok(()) => format!(
            "copied {} line(s), {} chars to the clipboard",
            text.lines().count().max(1),
            text.chars().count()
        ),
        Err(e) => format!("copy failed: {e}"),
    }
}

/// Flatten the transcript to plain (raw markdown) lines for copy mode.
fn transcript_copy_lines(transcript: &[ChatLine]) -> Vec<String> {
    let mut out = Vec::new();
    for (i, c) in transcript.iter().enumerate() {
        if i > 0 {
            out.push(String::new());
        }
        for l in c.text.lines() {
            out.push(l.to_string());
        }
    }
    out
}

/// Indices of transcript lines containing `query` (case-insensitive).
fn find_matches(lines: &[String], query: &str) -> Vec<usize> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return Vec::new();
    }
    lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.to_lowercase().contains(&q))
        .map(|(i, _)| i)
        .collect()
}

/// Refresh the cross-session search results for the current query.
fn refresh_session_search(engine: &ChatEngine, ss: &mut SessionSearch) {
    let q = ss.query.trim();
    ss.hits = if q.is_empty() {
        Vec::new()
    } else {
        engine.memory.search_messages(q, 100).unwrap_or_default()
    };
    if ss.sel >= ss.hits.len() {
        ss.sel = ss.hits.len().saturating_sub(1);
    }
}

/// Raw text of the most recent non-empty assistant reply.
fn last_reply_text(transcript: &[ChatLine]) -> String {
    transcript
        .iter()
        .rev()
        .find(|c| c.speaker == Speaker::Assistant && !c.text.trim().is_empty())
        .map(|c| c.text.clone())
        .unwrap_or_default()
}

/// Render the current conversation as a plaintext Markdown document.
fn session_markdown(engine: &ChatEngine, transcript: &[ChatLine]) -> String {
    let mut s = String::new();
    s.push_str(&format!("# Enclave session '{}'\n\n", engine.session.name));
    s.push_str(&format!(
        "- id: `{}`\n- provider: {}\n- model: {}\n",
        engine.session.id,
        engine.provider_name(),
        engine.model
    ));
    if let Some(effort) = &engine.reasoning_effort {
        s.push_str(&format!("- reasoning effort: {effort}\n"));
    }
    s.push('\n');
    for c in transcript {
        let heading = match c.speaker {
            Speaker::User => "## You",
            Speaker::Assistant => "## Assistant",
            Speaker::Tool => "## Tool",
            Speaker::System => "## System",
        };
        s.push_str(heading);
        s.push_str("\n\n");
        s.push_str(&c.text);
        s.push_str("\n\n");
    }
    s
}

/// A centered rectangle of the requested size, clamped to `area`.
fn centered_rect(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + area.width.saturating_sub(w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    }
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
    let egress = engine.memory.egress_count().unwrap_or(0);
    format!(
        "▮ privacy · encrypted db {size} · {sessions} sessions · {messages} messages · egress {egress} · AES-256 (SQLCipher) · guard {guard_label} · telemetry off"
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
    copy: Option<&CopyState>,
    find: Option<&FindState>,
    search: Option<&SessionSearch>,
    locked: bool,
    lock_input: &str,
    unfocused: bool,
    details: bool,
    palette: bool,
    palette_sel: usize,
    theme_picker: bool,
    theme_sel: usize,
    theme_current: &str,
    provider_picker: bool,
    provider_sel: usize,
    at_files: &[String],
    at_sel: usize,
    slash_matches: &[(String, String)],
    slash_sel: usize,
    graph: bool,
    graph_rows: &[GraphRow],
    graph_sel: usize,
) {
    let area = f.area();
    // Base background for the whole screen.
    f.render_widget(Block::default().style(Style::default().bg(pal().bg)), area);

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
            Span::styled(" ◆ ", Style::default().fg(pal().accent)),
            Span::styled(
                "enclave",
                Style::default().fg(pal().text).add_modifier(Modifier::BOLD),
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
            .style(Style::default().fg(pal().dim).bg(pal().surface)),
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
        if !details && entry.speaker == Speaker::Tool {
            continue;
        }
        let card = match entry.speaker {
            Speaker::User => Card {
                lines: entry
                    .text
                    .lines()
                    .map(|l| Line::from(Span::styled(l.to_string(), Style::default().fg(pal().text))))
                    .collect(),
                bg: pal().surface_hi,
                accent: pal().accent,
            },
            Speaker::Assistant => {
                let mut ls = markdown::render(&entry.text);
                if entry.text.trim().is_empty() {
                    ls = vec![Line::from(Span::styled(
                        "…",
                        Style::default().fg(pal().dim).add_modifier(Modifier::ITALIC),
                    ))];
                }
                Card {
                    lines: ls,
                    bg: pal().surface,
                    accent: pal().surface_hi,
                }
            }
            Speaker::System => Card {
                lines: vec![Line::from(Span::styled(
                    entry.text.clone(),
                    Style::default().fg(pal().dim).add_modifier(Modifier::ITALIC),
                ))],
                bg: pal().bg,
                accent: pal().bg,
            },
            Speaker::Tool => Card {
                lines: entry
                    .text
                    .lines()
                    .map(|l| {
                        // Diff lines get their own colours: + added, - removed.
                        let style = if l.starts_with('+') {
                            Style::default().fg(pal().green)
                        } else if l.starts_with('-') {
                            Style::default().fg(pal().red)
                        } else if l.starts_with("@@") || l.starts_with('…') {
                            Style::default().fg(pal().dim)
                        } else {
                            Style::default().fg(pal().yellow)
                        };
                        Line::from(Span::styled(l.to_string(), style))
                    })
                    .collect(),
                bg: pal().bg,
                accent: pal().bg,
            },
        };
        cards.push(card);
    }

    // Empty conversation: show the welcome screen with visible commands.
    if cards.is_empty() {
        cards.push(Card {
            lines: welcome_lines(tools_enabled),
            bg: pal().bg,
            accent: pal().bg,
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
            .style(Style::default().bg(card.bg).fg(pal().text))
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
                .style(Style::default().fg(pal().text).bg(pal().surface_hi))
                .block(Block::default().padding(Padding::new(2, 1, 0, 0)))
                .wrap(Wrap { trim: false });
            f.render_widget(warn, main[2]);
            accent_bar(f, main[2], pal().yellow);
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
                .style(Style::default().fg(pal().text).bg(pal().surface_hi))
                .block(Block::default().padding(Padding::new(2, 1, 0, 0)))
                .wrap(Wrap { trim: false });
            f.render_widget(warn, main[2]);
            accent_bar(f, main[2], pal().yellow);
        }
        _ => {
            let renaming = matches!(phase, Phase::Renaming { .. });
            let is_new = matches!(phase, Phase::Renaming { id: None });
            let accent = if renaming { pal().yellow } else { pal().accent };
            let prompt = if renaming { "› " } else { "❯ " };
            let placeholder = if is_new {
                "session name  (empty = 'chat')"
            } else if renaming {
                "new name"
            } else {
                "send a message…  ( /help commands · ? shortcuts )"
            };
            let (shown, body_fg) = if input.is_empty() {
                (format!("{prompt}{placeholder}"), pal().dim)
            } else {
                let mut it = input.splitn(2, '\n');
                let first = it.next().unwrap_or("");
                match it.next() {
                    Some(rest) => (format!("{prompt}{first}\n{rest}"), pal().text),
                    None => (format!("{prompt}{first}"), pal().text),
                }
            };
            let input_widget = Paragraph::new(shown)
                .style(Style::default().fg(body_fg).bg(pal().surface))
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
        Paragraph::new(format!(" {privacy}")).style(Style::default().fg(pal().dim).bg(pal().bg)),
        main[3],
    );

    // Footer: model chip left, key chips right (opencode style).
    let status_style = if status.starts_with("error") {
        Style::default().fg(pal().red)
    } else if matches!(
        phase,
        Phase::Confirming { .. } | Phase::ToolConfirm { .. } | Phase::Guard { .. }
    ) {
        Style::default().fg(pal().yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(pal().dim)
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
                .fg(pal().bg)
                .bg(pal().accent)
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
            Style::default().fg(pal().accent),
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
        overlay_bg(f, box_area, pal().accent);
        let mut lines = vec![Line::from(Span::styled(
            "shortcuts",
            Style::default().fg(pal().accent).add_modifier(Modifier::BOLD),
        ))];
        lines.extend(welcome_lines(tools_enabled));
        lines.push(plain_line(""));
        lines.push(Line::from(Span::styled(
            "  press any key to close",
            Style::default().fg(pal().dim),
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
        overlay_bg(f, box_area, pal().accent);
        let mut lines: Vec<Line> = vec![Line::from(Span::styled(
            "sessions",
            Style::default().fg(pal().accent).add_modifier(Modifier::BOLD),
        ))];
        if sessions.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no sessions yet — press n to create one",
                Style::default().fg(pal().dim),
            )));
        } else {
            for (i, s) in sessions.iter().enumerate() {
                let current = s.id == engine.session.id;
                let marker = if i == sel { "› " } else { "  " };
                let bullet = if current { "●" } else { "○" };
                let name: String = s.name.chars().take(26).collect();
                let style = if i == sel {
                    Style::default()
                        .fg(pal().bg)
                        .bg(pal().accent)
                        .add_modifier(Modifier::BOLD)
                } else if current {
                    Style::default().fg(pal().green)
                } else {
                    Style::default().fg(pal().text)
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
            Style::default().fg(pal().accent).add_modifier(Modifier::BOLD),
        ))];
        lines.push(Line::from(vec![
            Span::styled("  filter: ", Style::default().fg(pal().dim)),
            Span::styled(
                model_filter.to_string(),
                Style::default().fg(pal().text).add_modifier(Modifier::BOLD),
            ),
            Span::styled("▏", Style::default().fg(pal().accent)),
        ]));
        if let Some(acc) = account {
            let s = acc.summary();
            if s != "no account data" {
                lines.push(Line::from(vec![
                    Span::styled("  credits: ", Style::default().fg(pal().dim)),
                    Span::styled(s, Style::default().fg(pal().accent)),
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
                Style::default().fg(pal().dim),
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
                        .fg(pal().bg)
                        .bg(pal().accent)
                        .add_modifier(Modifier::BOLD)
                } else if current {
                    Style::default().fg(pal().green)
                } else {
                    Style::default().fg(pal().text)
                };
                let meta_style = if selected {
                    Style::default().fg(pal().bg).bg(pal().accent)
                } else {
                    Style::default().fg(pal().dim)
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
                Style::default().fg(pal().yellow),
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
        overlay_bg(f, box_area, pal().accent);
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
            Style::default().fg(pal().accent).add_modifier(Modifier::BOLD),
        ))];
        lines.push(Line::from(Span::styled(
            "  used by models that support it (OpenRouter/OpenAI)",
            Style::default().fg(pal().dim),
        )));
        for (i, (label, desc)) in EFFORT_OPTIONS.iter().enumerate() {
            let selected = i == effort_sel;
            let marker = if selected { "› " } else { "  " };
            let bullet = if *label == current { "●" } else { "○" };
            let row_style = if selected {
                Style::default()
                    .fg(pal().bg)
                    .bg(pal().accent)
                    .add_modifier(Modifier::BOLD)
            } else if *label == current {
                Style::default().fg(pal().green)
            } else {
                Style::default().fg(pal().text)
            };
            let desc_style = if selected {
                Style::default().fg(pal().bg).bg(pal().accent)
            } else {
                Style::default().fg(pal().dim)
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
        overlay_bg(f, box_area, pal().accent);
        let overlay = Paragraph::new(lines)
            .block(Block::default().padding(Padding::new(2, 1, 0, 0)));
        f.render_widget(overlay, box_area);
    }
    // Command palette (Ctrl-P): pick a slash command to insert into the input.
    if palette {
        let w = 72.min(area.width.saturating_sub(4));
        let max_rows = (area.height.saturating_sub(8) as usize).clamp(5, 24);
        let visible = PALETTE_COMMANDS.len().min(max_rows);
        let (start, end) = list_window(PALETTE_COMMANDS.len(), palette_sel, visible);
        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(Span::styled(
            format!("command palette · {}/{}", palette_sel + 1, PALETTE_COMMANDS.len()),
            Style::default().fg(pal().accent).add_modifier(Modifier::BOLD),
        )));
        for (j, (cmd, desc)) in PALETTE_COMMANDS[start..end].iter().enumerate() {
            let i = start + j;
            let selected = i == palette_sel;
            let cmd_style = if selected {
                Style::default().fg(pal().bg).bg(pal().accent).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(pal().accent)
            };
            let desc_style = if selected {
                Style::default().fg(pal().bg).bg(pal().accent)
            } else {
                Style::default().fg(pal().dim)
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{:<16}", cmd), cmd_style),
                Span::styled(desc.to_string(), desc_style),
            ]));
        }
        lines.push(Line::from(
            [chip("↑↓", "move"), chip("Enter", "insert"), chip("Esc", "close")]
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
        overlay_bg(f, box_area, pal().accent);
        f.render_widget(
            Paragraph::new(lines).block(Block::default().padding(Padding::new(2, 1, 0, 0))),
            box_area,
        );
    }
    // Theme picker (/theme with no argument).
    if theme_picker {
        let names = crate::tui::theme::names();
        let w = 46.min(area.width.saturating_sub(4));
        let mut lines: Vec<Line> = vec![Line::from(Span::styled(
            "theme",
            Style::default().fg(pal().accent).add_modifier(Modifier::BOLD),
        ))];
        for (i, name) in names.iter().enumerate() {
            let selected = i == theme_sel;
            let bullet = if *name == theme_current { "●" } else { "○" };
            let style = if selected {
                Style::default().fg(pal().bg).bg(pal().accent).add_modifier(Modifier::BOLD)
            } else if *name == theme_current {
                Style::default().fg(pal().green)
            } else {
                Style::default().fg(pal().text)
            };
            lines.push(Line::from(Span::styled(
                format!("{} {bullet} {name}", if selected { "›" } else { " " }),
                style,
            )));
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
        overlay_bg(f, box_area, pal().accent);
        f.render_widget(
            Paragraph::new(lines).block(Block::default().padding(Padding::new(2, 1, 0, 0))),
            box_area,
        );
    }
    // Provider picker (/connect).
    if provider_picker {
        let names = crate::providers::known_providers();
        let w = 56.min(area.width.saturating_sub(4));
        let mut lines: Vec<Line> = vec![Line::from(Span::styled(
            "provider — switch model backend",
            Style::default().fg(pal().accent).add_modifier(Modifier::BOLD),
        ))];
        for (i, name) in names.iter().enumerate() {
            let selected = i == provider_sel;
            let bullet = if *name == engine.provider_name() { "●" } else { "○" };
            let hint = if crate::providers::requires_api_key(name) {
                "needs an API key"
            } else {
                "local (no key)"
            };
            let style = if selected {
                Style::default().fg(pal().bg).bg(pal().accent).add_modifier(Modifier::BOLD)
            } else if *name == engine.provider_name() {
                Style::default().fg(pal().green)
            } else {
                Style::default().fg(pal().text)
            };
            let hint_style = if selected {
                Style::default().fg(pal().bg).bg(pal().accent)
            } else {
                Style::default().fg(pal().dim)
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{} {bullet} {name:<10}", if selected { "›" } else { " " }), style),
                Span::styled(hint.to_string(), hint_style),
            ]));
        }
        lines.push(Line::from(
            [chip("↑↓", "move"), chip("Enter", "switch"), chip("Esc", "close")]
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
        overlay_bg(f, box_area, pal().accent);
        f.render_widget(
            Paragraph::new(lines).block(Block::default().padding(Padding::new(2, 1, 0, 0))),
            box_area,
        );
    }
    // `@file` completion popup (anchored above the input box).
    // Slash-command autocomplete popup (appears as soon as you type `/`).
    if !slash_matches.is_empty() && !palette {
        let rows = slash_matches.len().min(10);
        let h = (rows as u16) + 2;
        let w = area.width.saturating_sub(4).min(72);
        let y = main[2].y.saturating_sub(h);
        let box_area = Rect {
            x: area.x + 2,
            y,
            width: w,
            height: h,
        };
        overlay_bg(f, box_area, pal().accent);
        let (start, end) = list_window(slash_matches.len(), slash_sel, rows);
        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(Span::styled(
            format!(" commands · {}/{}", slash_sel + 1, slash_matches.len()),
            Style::default()
                .fg(pal().accent)
                .add_modifier(Modifier::BOLD),
        )));
        for (i, (cmd, desc)) in slash_matches.iter().enumerate().take(end).skip(start) {
            let selected = i == slash_sel;
            let style = if selected {
                Style::default()
                    .fg(pal().bg)
                    .bg(pal().accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(pal().text)
            };
            let desc_style = if selected {
                Style::default().fg(pal().bg)
            } else {
                Style::default().fg(pal().dim)
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {:<16}", cmd), style),
                Span::styled(truncate(desc, 46), desc_style),
            ]));
        }
        f.render_widget(
            Paragraph::new(lines).block(Block::default().padding(Padding::new(1, 1, 0, 0))),
            box_area,
        );
    }
    if !at_files.is_empty() {
        let rows = at_files.len().min(8);
        let h = (rows as u16) + 2;
        let w = area.width.saturating_sub(4).min(64);
        let y = main[2].y.saturating_sub(h);
        let box_area = Rect {
            x: area.x + 2,
            y,
            width: w,
            height: h,
        };
        overlay_bg(f, box_area, pal().accent);
        let (start, end) = list_window(at_files.len(), at_sel, rows);
        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(Span::styled(
            format!(" @files · {}/{}", at_sel + 1, at_files.len()),
            Style::default()
                .fg(pal().accent)
                .add_modifier(Modifier::BOLD),
        )));
        for (i, file) in at_files.iter().enumerate().take(end).skip(start) {
            let selected = i == at_sel;
            let style = if selected {
                Style::default()
                    .fg(pal().bg)
                    .bg(pal().accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(pal().text)
            };
            lines.push(Line::from(Span::styled(
                format!("  {}", truncate(file, 56)),
                style,
            )));
        }
        f.render_widget(
            Paragraph::new(lines).block(Block::default().padding(Padding::new(1, 1, 0, 0))),
            box_area,
        );
    }
    // Conversation-branch graph (navigable): ↑/↓ select, Enter opens a branch.
    if graph {
        let rows = graph_rows.len().min(20);
        let h = (rows as u16) + 2;
        let w = area.width.saturating_sub(6).clamp(30, 80);
        let box_area = centered_rect(area, w, h);
        overlay_bg(f, box_area, pal().accent);
        let (start, end) = list_window(graph_rows.len(), graph_sel, rows);
        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(Span::styled(
            format!(" branch graph · {}/{}", graph_sel + 1, graph_rows.len()),
            Style::default()
                .fg(pal().accent)
                .add_modifier(Modifier::BOLD),
        )));
        for (i, row) in graph_rows.iter().enumerate().take(end).skip(start) {
            let selected = i == graph_sel;
            let style = if selected {
                Style::default()
                    .fg(pal().bg)
                    .bg(pal().accent)
                    .add_modifier(Modifier::BOLD)
            } else if row.is_current {
                Style::default().fg(pal().green).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(pal().text)
            };
            lines.push(Line::from(Span::styled(format!("  {}", row.label), style)));
        }
        f.render_widget(
            Paragraph::new(lines).block(Block::default().padding(Padding::new(1, 1, 0, 0))),
            box_area,
        );
    }
    // Copy-mode overlay (Ctrl+Y): visual line selection yanked to the clipboard.
    if let Some(cs) = copy {
        let w = area.width.saturating_sub(8).clamp(24, 100);
        let max_rows = (area.height.saturating_sub(8) as usize).clamp(3, 30);
        let (a, b) = if cs.anchor <= cs.sel {
            (cs.anchor, cs.sel)
        } else {
            (cs.sel, cs.anchor)
        };
        let visible = cs.lines.len().min(max_rows);
        let (start, end) = list_window(cs.lines.len(), cs.sel, visible);
        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(Span::styled(
            format!(
                "copy — {} line(s) selected · y copy · a all · e last reply · Esc",
                b.saturating_sub(a) + 1
            ),
            Style::default().fg(pal().accent).add_modifier(Modifier::BOLD),
        )));
        for i in start..end {
            let selected = i >= a && i <= b;
            let style = if selected {
                Style::default().fg(pal().bg).bg(pal().accent)
            } else {
                Style::default().fg(pal().text)
            };
            let num_style = if selected {
                style
            } else {
                Style::default().fg(pal().dim)
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{:>4} ", i + 1), num_style),
                Span::styled(cs.lines[i].clone(), style),
            ]));
        }
        lines.push(Line::from(
            [
                chip("↑↓", "select"),
                chip("PgUp/PgDn", "page"),
                chip("y", "copy"),
                chip("a", "all"),
                chip("e", "last reply"),
                chip("Esc", "cancel"),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<Span>>(),
        ));
        let h = (lines.len() as u16 + 2).min(area.height.saturating_sub(1));
        let box_area = centered_rect(area, w, h);
        overlay_bg(f, box_area, pal().accent);
        let overlay =
            Paragraph::new(lines).block(Block::default().padding(Padding::new(2, 1, 0, 0)));
        f.render_widget(overlay, box_area);
    }
    // In-transcript search overlay (/find): live substring matches.
    if let Some(fs) = find {
        let all = transcript_copy_lines(transcript);
        let matches = find_matches(&all, &fs.query);
        let w = area.width.saturating_sub(8).clamp(24, 100);
        let max_rows = (area.height.saturating_sub(8) as usize).clamp(3, 30);
        let visible = matches.len().min(max_rows);
        let (start, end) = list_window(matches.len(), fs.sel, visible);
        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(vec![
            Span::styled(
                "find ",
                Style::default().fg(pal().accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled(fs.query.clone(), Style::default().fg(pal().text)),
            Span::styled(
                format!("   {} match(es)", matches.len()),
                Style::default().fg(pal().dim),
            ),
        ]));
        if matches.is_empty() {
            lines.push(plain_line("  no matches — keep typing (Ctrl-U clears), Esc closes"));
        } else {
            for (rank, &idx) in matches[start..end].iter().enumerate() {
                let selected = start + rank == fs.sel;
                let style = if selected {
                    Style::default().fg(pal().bg).bg(pal().accent)
                } else {
                    Style::default().fg(pal().text)
                };
                let num_style = if selected {
                    style
                } else {
                    Style::default().fg(pal().dim)
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("{:>4} ", idx + 1), num_style),
                    Span::styled(all[idx].clone(), style),
                ]));
            }
        }
        lines.push(Line::from(
            [
                chip("↑↓", "select"),
                chip("Enter", "copy line"),
                chip("Esc", "close"),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<Span>>(),
        ));
        let h = (lines.len() as u16 + 2).min(area.height.saturating_sub(1));
        let box_area = centered_rect(area, w, h);
        overlay_bg(f, box_area, pal().accent);
        let overlay =
            Paragraph::new(lines).block(Block::default().padding(Padding::new(2, 1, 0, 0)));
        f.render_widget(overlay, box_area);
    }
    // Cross-session search overlay (Ctrl-R): hits from the encrypted DB.
    if let Some(ss) = search {
        let w = area.width.saturating_sub(8).clamp(24, 100);
        let max_rows = (area.height.saturating_sub(8) as usize).clamp(3, 30);
        let visible = ss.hits.len().min(max_rows);
        let (start, end) = list_window(ss.hits.len(), ss.sel, visible);
        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(vec![
            Span::styled(
                "search ",
                Style::default().fg(pal().accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled(ss.query.clone(), Style::default().fg(pal().text)),
            Span::styled(
                format!("   {} hit(s) across sessions", ss.hits.len()),
                Style::default().fg(pal().dim),
            ),
        ]));
        if ss.hits.is_empty() {
            lines.push(plain_line("  type to search the encrypted database, Enter opens, Esc closes"));
        } else {
            for (rank, h) in ss.hits[start..end].iter().enumerate() {
                let selected = start + rank == ss.sel;
                let style = if selected {
                    Style::default().fg(pal().bg).bg(pal().accent)
                } else {
                    Style::default().fg(pal().text)
                };
                let meta_style = if selected {
                    style
                } else {
                    Style::default().fg(pal().dim)
                };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  {:<20} ", truncate(&h.session_name, 20)),
                        meta_style,
                    ),
                    Span::styled(format!("[{}] ", h.role), meta_style),
                    Span::styled(h.snippet.clone(), style),
                ]));
            }
        }
        lines.push(Line::from(
            [
                chip("↑↓", "select"),
                chip("Enter", "open session"),
                chip("Esc", "close"),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<Span>>(),
        ));
        let h = (lines.len() as u16 + 2).min(area.height.saturating_sub(1));
        let box_area = centered_rect(area, w, h);
        overlay_bg(f, box_area, pal().accent);
        let overlay =
            Paragraph::new(lines).block(Block::default().padding(Padding::new(2, 1, 0, 0)));
        f.render_widget(overlay, box_area);
    }
    if let Phase::Guard { text, findings } = phase {
        let box_area = overlay_rect(area);
        overlay_bg(f, box_area, pal().red);
        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(Span::styled(
            "⚠ privacy guard · sensitive data detected",
            Style::default().fg(pal().red).add_modifier(Modifier::BOLD),
        )));
        lines.push(plain_line(""));
        lines.push(Line::from(Span::styled(
            "  what will leave this machine if you send:",
            Style::default().fg(pal().dim),
        )));
        for fd in findings {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {:<12}", fd.kind.label()),
                    Style::default().fg(pal().yellow),
                ),
                Span::styled(fd.text.clone(), Style::default().fg(pal().text)),
            ]));
        }
        lines.push(plain_line(""));
        lines.push(Line::from(Span::styled(
            "  message preview:",
            Style::default().fg(pal().dim),
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
            Style::default().fg(pal().dim),
        )));
        lines.push(Line::from(Span::styled(
            "  re-sent on later turns — original text stays encrypted on disk",
            Style::default().fg(pal().dim),
        )));
        let overlay = Paragraph::new(lines)
            .block(Block::default().padding(Padding::new(3, 1, 0, 0)))
            .wrap(Wrap { trim: false });
        f.render_widget(overlay, box_area);
    }

    // A4: lock screen (auto-lock after idle).
    if locked {
        f.render_widget(Clear, area);
        f.render_widget(Block::default().style(Style::default().bg(pal().bg)), area);
        let w = 46.min(area.width.saturating_sub(2));
        let box_area = centered_rect(area, w, 6);
        overlay_bg(f, box_area, pal().accent);
        let masked = "•".repeat(lock_input.chars().count());
        let lines = vec![
            Line::from(Span::styled(
                "🔒 locked",
                Style::default()
                    .fg(pal().accent)
                    .add_modifier(Modifier::BOLD),
            )),
            plain_line(""),
            Line::from(Span::styled(
                "  master password",
                Style::default().fg(pal().dim),
            )),
            Line::from(Span::styled(
                format!("  {masked}"),
                Style::default().fg(pal().text),
            )),
            Line::from(Span::styled(
                "  Enter to unlock · Ctrl-C to quit",
                Style::default().fg(pal().dim),
            )),
        ];
        let overlay =
            Paragraph::new(lines).block(Block::default().padding(Padding::new(2, 1, 0, 0)));
        f.render_widget(overlay, box_area);
    }

    // A4: when the window loses focus, obscure everything (drawn last).
    if unfocused {
        f.render_widget(Clear, area);
        f.render_widget(Block::default().style(Style::default().bg(pal().bg)), area);
        let msg = Rect {
            x: area.x,
            y: area.y + area.height / 2,
            width: area.width,
            height: 1,
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "· paused — window not focused ·",
                Style::default().fg(pal().dim),
            )))
            .alignment(Alignment::Center),
            msg,
        );
    }
}

/// Fill an overlay rectangle with a raised surface colour and a left accent
/// edge (no borders).
fn overlay_bg(f: &mut Frame, area: Rect, accent: Color) {
    f.render_widget(Clear, area);
    f.render_widget(
        Block::default().style(Style::default().bg(pal().surface_hi)),
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

/// Suspend the TUI, edit the current input in $VISUAL/$EDITOR, and return it.
fn edit_in_editor(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    current: &str,
) -> Result<String> {
    use std::io::Write;
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string());
    let mut path = std::env::temp_dir();
    path.push(format!("enclave-input-{}.md", std::process::id()));
    std::fs::write(&path, current)
        .map_err(|e| crate::error::EnclaveError::other(format!("cannot write temp file: {e}")))?;

    let _ = disable_raw_mode();
    let _ = execute!(std::io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
    let _ = std::io::stdout().flush();
    let status = std::process::Command::new(&editor).arg(&path).status();
    let _ = execute!(std::io::stdout(), EnterAlternateScreen, EnableMouseCapture);
    let _ = enable_raw_mode();
    let _ = terminal.clear();

    let result = match status {
        Ok(_) => std::fs::read_to_string(&path)
            .map_err(|e| crate::error::EnclaveError::other(format!("cannot read temp file: {e}"))),
        Err(e) => Err(crate::error::EnclaveError::other(format!(
            "could not launch editor '{editor}': {e}"
        ))),
    };
    let _ = std::fs::remove_file(&path);
    result
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

/// Remember the chosen theme across launches.
fn persist_theme(name: &str) {
    let name = name.to_string();
    persist_settings(move |s| s.tui.theme = Some(name));
}

fn plain_line(s: &str) -> Line<'static> {
    Line::from(s.to_string())
}

/// Render recorded decisions as an aligned, multi-line block.
fn decisions_to_text(ds: &[crate::privacy::Decision]) -> String {
    ds.iter()
        .map(|d| {
            let tags = if d.tags.trim().is_empty() {
                String::new()
            } else {
                format!("  #{}", d.tags.replace(',', " #"))
            };
            let first = d.body.lines().next().unwrap_or("");
            if first.is_empty() {
                format!("{}  [{}] {}{}", &d.id[..8.min(d.id.len())], d.status, truncate(&d.title, 70), tags)
            } else {
                format!(
                    "{}  [{}] {}{}\n        {}",
                    &d.id[..8.min(d.id.len())],
                    d.status,
                    truncate(&d.title, 60),
                    tags,
                    truncate(first, 80)
                )
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build the "privacy blast-radius" + score text for the TUI.
fn exposure_text(
    engine: &ChatEngine,
    guard: &GuardSettings,
    tools: &ToolsSettings,
) -> crate::error::Result<String> {
    use crate::privacy::exposure::{ScoreInputs, blast_radius, privacy_score};

    let summary = engine.memory.egress_summary(None)?;
    let br = blast_radius(&summary);
    let redactions: i64 = summary.kinds.iter().map(|(_, c)| *c).sum();
    let local_only_memories = engine
        .memory
        .list_memories(1000)?
        .iter()
        .filter(|m| m.local_only)
        .count() as i64;

    let size = fmt_bytes(br.bytes.max(0) as u64);
    let mut out = String::new();
    out.push_str(&format!(
        "privacy blast-radius — {} outbound request(s): {} remote · {} local · {} redacted · {size} sent\n",
        br.total,
        br.remote,
        br.local,
        br.redacted,
    ));
    if br.providers.is_empty() {
        out.push_str("providers: (nothing recorded)\n");
    } else {
        let p: Vec<String> = br.providers.iter().map(|(n, c)| format!("{n}×{c}")).collect();
        out.push_str(&format!("providers: {}\n", p.join(", ")));
    }
    if br.kinds.is_empty() {
        out.push_str("sensitive caught: none\n");
    } else {
        let k: Vec<String> = br.kinds.iter().map(|(n, c)| format!("{n}×{c}")).collect();
        out.push_str(&format!("sensitive caught: {}\n", k.join(", ")));
    }

    let inputs = ScoreInputs {
        remote: br.remote,
        local: br.local,
        redactions,
        air_gap: engine.air_gap,
        route_sensitive: engine.route_sensitive,
        guard_enabled: guard.enabled,
        taint: engine.taint,
        sandbox_on: tools.sandbox != crate::config::SandboxMode::Off,
        anonymised_network: false,
        local_only_memories,
    };
    let score = privacy_score(&inputs);
    out.push_str(&format!(
        "\nprivacy score: {} / 100 (grade {})",
        score.score, score.grade
    ));
    Ok(out)
}

/// Explain what Enclave puts into the context this turn ("why is this in
/// context?"): the composition of the system message plus the history size,
/// any active redactions and the taint status.
fn context_text(engine: &ChatEngine) -> String {
    let r = engine.context_report();
    let mut out = String::new();
    out.push_str(&format!(
        "context this turn — provider {} · model {} · mode {}\n",
        r.provider, r.model, r.mode
    ));
    out.push_str("system message:\n");
    if r.parts.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for p in &r.parts {
            out.push_str(&format!(
                "  • {:<22} {:>6} chars  — {}\n",
                p.label, p.chars, p.detail
            ));
        }
    }
    out.push_str(&format!(
        "history: {} message(s) · {} chars\n",
        r.messages, r.history_chars
    ));
    if r.redactions.is_empty() {
        out.push_str("redactions: none\n");
    } else {
        out.push_str(&format!("redactions: {}\n", r.redactions));
    }
    out.push_str(&format!(
        "taint: {}\ntotal sent: {} chars",
        if r.taint { "on (flagged turns re-redacted)" } else { "off" },
        r.total_chars
    ));
    out
}

/// Truncate a string to `n` characters (appending an ellipsis when cut).
fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// Render a list of memories as an aligned, multi-line block.
fn memories_to_text(mems: &[crate::privacy::Memory]) -> String {
    mems.iter()
        .map(|m| {
            let mut marks = Vec::new();
            if m.pinned {
                marks.push("pinned");
            }
            if m.local_only {
                marks.push("local-only");
            }
            let mark = if marks.is_empty() {
                String::new()
            } else {
                format!("  [{}]", marks.join(","))
            };
            let tags = if m.tags.trim().is_empty() {
                String::new()
            } else {
                format!("  #{}", m.tags.replace(',', " #"))
            };
            format!(
                "{}  {}{}{}",
                &m.id[..8.min(m.id.len())],
                truncate(&m.text, 70),
                tags,
                mark
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
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
                .fg(pal().bg)
                .bg(pal().surface_hi)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!(" {label} "), Style::default().fg(pal().dim)),
    ]
}

/// Welcome screen shown when the conversation is empty.
fn welcome_lines(tools_enabled: bool) -> Vec<Line<'static>> {
    let plain = |s: &str| Line::from(s.to_string());
    let dim = |s: &str| Line::from(Span::styled(s.to_string(), Style::default().fg(pal().dim)));
    let key = |k: &str, d: &str| {
        Line::from(vec![
            Span::styled(
                format!("  {k:<10}"),
                Style::default().fg(pal().accent).add_modifier(Modifier::BOLD),
            ),
            Span::raw(d.to_string()),
        ])
    };

    let mut v = vec![
        Line::from(Span::styled(
            "◆ ENCLAVE",
            Style::default().fg(pal().accent).add_modifier(Modifier::BOLD),
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
        key("/branch", "fork a branch (use --from N to fork from an earlier message)"),
        key("/log", "show the conversation branch tree"),
        key("/checkout", "switch to a branch by name or id"),
        key("/diff", "compare two sessions (branch diff)"),
        key("/merge", "merge a branch's new turns into this one"),
        key("/graph", "navigable branch graph (Enter opens a branch)"),
        key("/blame", "locate which turn/branch introduced some text"),
        key("/provenance", "what left the machine for this session"),
        key("/clear", "wipe the current session"),
        key("/model", "pick a model from the list (saved for next launches)"),
        key("/effort", "reasoning effort (a picker opens right after /model)"),
        key("/plan", "plan mode — read-only, no edits or shell (also Shift+Tab)"),
        key("/build", "build mode — full access within the permission policy"),
        key("/attach", "attach an image or text file to your next message"),
        key("/detach", "clear pending attachments"),
        key("/find", "search this conversation (also Ctrl-F)"),
        key("/search", "search across all saved sessions (also Ctrl-R)"),
        key("/export", "export this chat: /export html|md|pdf [path]"),
        key("/editor", "open the message box in $EDITOR (also Ctrl-O)"),
        key("/init", "generate an AGENTS.md for this project"),
        key("/mcp", "list tools exposed by connected MCP servers"),
        key("/ledger", "show the encrypted egress ledger (what left the machine)"),
        key("/rag", "local file index: /rag index <paths> · /rag search <q> · /rag status"),
        key("/airgap", "air-gap mode: refuse to send to remote providers (on|off)"),
        key("/route", "route sensitive turns to local Ollama (on|off)"),
        key("/remember", "save a fact to encrypted memory: /remember text #tag"),
        key("/memory", "list memories (/memory search <q> · /memory pin <id>)"),
        key("/forget", "delete a memory by id or text"),
        key("/checkpoint", "summarise this session into long-term memory"),
        key("/decide", "record a decision: /decide title :: rationale"),
        key("/decisions", "list or search recorded decisions"),
        key("/exposure", "privacy blast-radius and posture score"),
        key("/context", "explain what is sent this turn (why is this in context?)"),
        key("/copy", "copy the last reply (or the last N replies: /copy 3)"),
        key("/save", "save this conversation as a Markdown file (plaintext)"),
        key("/undo /redo", "undo the last turn / restore it"),
        key("/retry", "regenerate the last reply"),
        key("/compact", "summarise the history to shrink the context"),
        key("/theme", "colour theme: default · nord · gruvbox · solarized · mono"),
        key("/commands", "list your custom .md commands"),
        key("/credits", "show OpenRouter credit / usage / limits"),
        key("/panic", "lock now: hide the transcript behind the master password"),
        key("/quit", "leave"),
        plain(""),
        Line::from(Span::styled(
            "KEYS",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        key("@file", "include a file in your message: @src/main.rs or @notes.md"),
        key("!cmd", "run a shell command locally — the output never leaves the machine"),
        key("Ctrl-Y", "copy mode: select transcript lines and yank to clipboard"),
        key("Ctrl-P", "command palette (pick any /command)"),
        key("Ctrl-N", "next message from your input history"),
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

    let label = |k: &str| Span::styled(format!("{k:<9}"), Style::default().fg(pal().dim));
    let mut lines: Vec<Line> = vec![Line::from(Span::styled(
        "info",
        Style::default().fg(pal().accent).add_modifier(Modifier::BOLD),
    ))];
    lines.push(Line::from(vec![
        label("session"),
        Span::styled(
            engine.session.name.clone(),
            Style::default().fg(pal().text).add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(vec![label("id"), Span::raw(id)]));
    lines.push(Line::from(vec![
        label("model"),
        Span::styled(engine.model.clone(), Style::default().fg(pal().accent)),
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
        label("mode"),
        Span::styled(
            engine.mode.label().to_string(),
            Style::default().fg(if engine.mode.is_plan() { pal().yellow } else { pal().text }),
        ),
    ]));
    if let Some(rules) = &engine.rules {
        let first = rules.lines().next().unwrap_or("").to_string();
        let short: String = first.chars().take(40).collect();
        lines.push(Line::from(vec![
            label("rules"),
            Span::styled(format!("{short}…"), Style::default().fg(pal().dim)),
        ]));
    }
    lines.push(Line::from(vec![
        label("context"),
        Span::raw(format!("~{est_tokens} tok · {transcript_len} lines")),
    ]));
    if let Some(acc) = account {
        let s = acc.summary();
        if s != "no account data" {
            lines.push(Line::from(vec![
                label("credits"),
                Span::styled(s, Style::default().fg(pal().accent)),
            ]));
        }
    }
    lines.push(Line::from(vec![
        label("tools"),
        Span::raw(if tools_enabled { "on" } else { "off" }),
    ]));
    lines.push(Line::from(vec![label("guard"), Span::raw(guard_state.to_string())]));
    lines.push(Line::from(vec![
        label("air-gap"),
        Span::styled(
            if engine.air_gap { "on (local only)" } else { "off" },
            Style::default().fg(if engine.air_gap { pal().yellow } else { pal().dim }),
        ),
    ]));
    lines.push(Line::from(vec![
        label("routing"),
        Span::styled(
            if engine.route_sensitive { "sensitive → local" } else { "off" },
            Style::default().fg(if engine.route_sensitive { pal().green } else { pal().dim }),
        ),
    ]));
    lines.push(plain_line(""));
    lines.push(Line::from(Span::styled(
        "STORAGE",
        Style::default().fg(pal().dim).add_modifier(Modifier::BOLD),
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
        Style::default().fg(pal().dim).add_modifier(Modifier::BOLD),
    )));
    if changes.is_empty() {
        lines.push(Line::from(Span::styled(
            "no changes yet",
            Style::default().fg(pal().dim),
        )));
    } else {
        for c in changes.iter().rev().take(12) {
            lines.push(Line::from(vec![
                Span::styled(format!("+{} ", c.added), Style::default().fg(pal().green)),
                Span::styled(format!("−{} ", c.removed), Style::default().fg(pal().red)),
                Span::styled(c.path.clone(), Style::default().fg(pal().text)),
            ]));
        }
    }

    let todos = engine.todos.lock().map(|t| t.clone()).unwrap_or_default();
    if !todos.is_empty() {
        lines.push(plain_line(""));
        lines.push(Line::from(Span::styled(
            "TASKS",
            Style::default().fg(pal().dim).add_modifier(Modifier::BOLD),
        )));
        for t in todos.iter().take(12) {
            let (mark, color) = match t.status.as_str() {
                "done" | "completed" | "x" => ("[x] ", pal().green),
                "in_progress" | "doing" | "~" => ("[~] ", pal().yellow),
                _ => ("[ ] ", pal().text),
            };
            lines.push(Line::from(vec![
                Span::styled(mark, Style::default().fg(color)),
                Span::styled(truncate(&t.text, 40), Style::default().fg(pal().text)),
            ]));
        }
    }

    let panel = Paragraph::new(lines)
        .style(Style::default().bg(pal().surface))
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
        Style::default().fg(pal().accent).add_modifier(Modifier::BOLD),
    ))];
    if sessions.is_empty() {
        lines.push(Line::from(Span::styled(
            "no sessions",
            Style::default().fg(pal().dim),
        )));
    }
    for (i, s) in sessions.iter().enumerate() {
        let marker = if s.id == engine.session.id { "●" } else { "○" };
        let name: String = s.name.chars().take(18).collect();
        let style = if i == sel {
            Style::default()
                .fg(pal().text)
                .bg(pal().surface_hi)
                .add_modifier(Modifier::BOLD)
        } else if s.id == engine.session.id {
            Style::default().fg(pal().text)
        } else {
            Style::default().fg(pal().dim)
        };
        lines.push(Line::from(Span::styled(
            format!("{marker} {name} ({})", s.message_count),
            style,
        )));
    }
    let list = Paragraph::new(lines)
        .style(Style::default().bg(pal().surface))
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
    fn transcript_copy_lines_keep_raw_text_and_separators() {
        let transcript = vec![
            ChatLine {
                speaker: Speaker::User,
                text: "hello".to_string(),
            },
            ChatLine {
                speaker: Speaker::Assistant,
                text: "line one\nline two".to_string(),
            },
        ];
        let lines = transcript_copy_lines(&transcript);
        assert_eq!(lines, vec!["hello", "", "line one", "line two"]);
    }

    #[test]
    fn last_reply_text_picks_most_recent_non_empty_assistant() {
        let transcript = vec![
            ChatLine {
                speaker: Speaker::Assistant,
                text: "first".to_string(),
            },
            ChatLine {
                speaker: Speaker::User,
                text: "again".to_string(),
            },
            ChatLine {
                speaker: Speaker::Assistant,
                text: "second".to_string(),
            },
            ChatLine {
                speaker: Speaker::Assistant,
                text: "   ".to_string(),
            },
        ];
        assert_eq!(last_reply_text(&transcript), "second");
    }

    #[test]
    fn centered_rect_is_centered_and_clamped() {
        let area = Rect {
            x: 0,
            y: 0,
            width: 100,
            height: 40,
        };
        let r = centered_rect(area, 50, 20);
        assert_eq!((r.x, r.y, r.width, r.height), (25, 10, 50, 20));
        let tiny = centered_rect(area, 500, 500);
        assert_eq!((tiny.x, tiny.y, tiny.width, tiny.height), (0, 0, 100, 40));
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
//! Local-first web UI — a graphical frontend next to the TUI.
//!
//! Serves an **interactive** view of the encrypted memory over `127.0.0.1`
//! only. Nothing is sent anywhere: the page and its assets are embedded in the
//! binary, the bind address is loopback, and every API call must present a
//! random per-run token. The same core (providers, guard, policy, ledger,
//! Conversation Git) stays untouched — this is just another face on the same
//! engine, styled to match the TUI.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::StreamExt;
use serde_json::{json, Value};

use crate::config::{Action, GuardSettings, ToolsSettings};
use crate::core::engine::{AgentStep, ChatEngine};
use crate::core::message::ToolCall;
use crate::error::{EnclaveError, Result};

#[derive(Clone)]
struct AppState {
    engine: Arc<tokio::sync::Mutex<ChatEngine>>,
    token: String,
    tools_enabled: bool,
    guard_label: String,
    tools: ToolsSettings,
    agent: Arc<AtomicBool>,
}

fn agent_on(state: &AppState) -> bool {
    state.agent.load(Ordering::Relaxed)
}

/// Serve the local web UI until interrupted. Binds loopback only.
pub async fn serve(
    engine: ChatEngine,
    tools: ToolsSettings,
    guard: GuardSettings,
    port: u16,
) -> Result<()> {
    let token = hex::encode(crate::privacy::crypto::random_bytes(16));
    let guard_label = guard_label(&guard);
    let state = AppState {
        engine: Arc::new(tokio::sync::Mutex::new(engine)),
        token: token.clone(),
        tools_enabled: tools.enabled,
        guard_label,
        tools,
        agent: Arc::new(AtomicBool::new(false)),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/api/state", get(api_state))
        .route("/api/files", get(api_files))
        .route("/api/file", get(api_file))
        .route("/api/search", get(api_search))
        .route("/api/graph", get(api_graph))
        .route("/api/models", get(api_models))
        .route("/api/scan", post(api_scan))
        .route("/api/session/:id", get(api_session))
        .route("/api/session/:id/load", post(api_session_load))
        .route("/api/session/:id/rename", post(api_session_rename))
        .route("/api/session/:id/delete", post(api_session_delete))
        .route("/api/session/new", post(api_session_new))
        .route("/api/branch", post(api_branch))
        .route("/api/checkout", post(api_checkout))
        .route("/api/merge", post(api_merge))
        .route("/api/init", post(api_init))
        .route("/api/diff", get(api_diff))
        .route("/api/send", post(api_send))
        .route("/api/agent/start", post(api_agent_start))
        .route("/api/agent/resume", post(api_agent_resume))
        .route("/api/model", post(api_model))
        .route("/api/effort", post(api_effort))
        .route("/api/provider", post(api_provider))
        .route("/api/history", post(api_history))
        .route("/api/toggle", post(api_toggle))
        .route("/api/memories", get(api_memories).post(api_memory_add))
        .route("/api/memories/delete", post(api_memory_delete))
        .route("/api/decisions", get(api_decisions).post(api_decision_add))
        .route("/api/decisions/delete", post(api_decision_delete))
        .route("/api/exposure", get(api_exposure))
        .route("/api/context", get(api_context))
        .route("/api/ledger", get(api_ledger))
        .route("/api/rag", post(api_rag))
        .route("/api/export", post(api_export))
        .route("/api/shell", post(api_shell))
        .with_state(state);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| EnclaveError::other(format!("cannot bind {addr}: {e}")))?;

    println!("Enclave web UI (local only) → http://127.0.0.1:{port}/?token={token}");
    println!("Loopback bind, per-run token, embedded assets. Nothing leaves this machine.");
    println!("Press Ctrl-C to stop.");

    axum::serve(listener, app)
        .await
        .map_err(|e| EnclaveError::other(format!("server error: {e}")))?;
    Ok(())
}

fn guard_label(guard: &GuardSettings) -> String {
    if !guard.enabled {
        return "off".to_string();
    }
    let mode = match &guard.mode {
        crate::config::GuardMode::Ask => "ask",
        crate::config::GuardMode::Redact => "auto",
        crate::config::GuardMode::Block => "block",
    };
    format!("on({mode})")
}

fn authorized(state: &AppState, headers: &HeaderMap, q: &HashMap<String, String>) -> bool {
    if let Some(t) = q.get("token") {
        if t == &state.token {
            return true;
        }
    }
    headers
        .get("x-enclave-token")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == state.token)
        .unwrap_or(false)
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// Build the full state snapshot while the engine lock is held.
fn state_json(engine: &ChatEngine, tools_enabled: bool, guard_label: &str, agent: bool) -> Value {
    let sessions = engine.memory.list_sessions().unwrap_or_default();
    let (n_sessions, n_messages) = engine
        .memory
        .stats()
        .map(|s| (s.sessions, s.messages))
        .unwrap_or((0, 0));
    let todos = engine.todos.lock().map(|t| t.clone()).unwrap_or_default();
    json!({
        "provider": engine.provider_name(),
        "model": engine.model,
        "effort": engine.reasoning_effort.clone().unwrap_or_else(|| "default".into()),
        "mode": engine.mode.label(),
        "guard": guard_label,
        "tools": tools_enabled,
        "agent": agent,
        "air_gap": engine.air_gap,
        "route_sensitive": engine.route_sensitive,
        "injection": engine.injection,
        "rules": engine.rules.clone(),
        "workspace": engine.workspace.display().to_string(),
        "session": { "id": engine.session.id, "name": engine.session.name },
        "sessions": sessions.iter().map(|s| json!({
            "id": s.id, "name": s.name,
            "message_count": s.message_count, "updated_at": s.updated_at,
        })).collect::<Vec<_>>(),
        "db_bytes": engine.memory.disk_bytes(),
        "egress_count": engine.memory.egress_count().unwrap_or(0),
        "memories_count": engine.memory.memory_count().unwrap_or(0),
        "decisions_count": engine.memory.decision_count().unwrap_or(0),
        "stats": { "sessions": n_sessions, "messages": n_messages },
        "todos": todos.iter().map(|t| json!({ "text": t.text, "status": t.status })).collect::<Vec<_>>(),
        "mcp_tools": engine.mcp.as_ref().map(|m| m.tool_names()).unwrap_or_default(),
    })
}

fn msg_json(m: &crate::core::message::Message) -> Value {
    json!({
        "role": m.role.as_str(),
        "content": m.content,
        "tainted": m.tainted,
        "tool_calls": m.tool_calls.iter().map(|c| json!({
            "name": c.name, "arguments": c.arguments,
        })).collect::<Vec<_>>(),
        "attachments": m.attachments.iter().map(|a| {
            let mut v = json!({
                "kind": if a.is_image() { "image" } else { "text" },
                "name": a.name,
                "mime": a.mime,
            });
            if a.is_image() && !a.data.is_empty() {
                v["url"] = json!(a.data_url());
            }
            v
        }).collect::<Vec<_>>(),
    })
}

async fn api_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let engine = state.engine.lock().await;
    Json(state_json(
        &engine,
        state.tools_enabled,
        &state.guard_label,
        agent_on(&state),
    ))
    .into_response()
}

async fn api_session(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let engine = state.engine.lock().await;
    let messages = engine.memory.get_history(&id, 100_000).unwrap_or_default();
    Json(json!({
        "id": id,
        "messages": messages.iter().map(msg_json).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn api_session_load(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let mut engine = state.engine.lock().await;
    match crate::core::session::Session::load(&engine.memory, &id) {
        Ok(sess) => {
            engine.session = sess;
            Json(state_json(
                &engine,
                state.tools_enabled,
                &state.guard_label,
                agent_on(&state),
            ))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_session_rename(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let name = body["name"].as_str().unwrap_or("").trim().to_string();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "name is required" })),
        )
            .into_response();
    }
    let mut engine = state.engine.lock().await;
    if let Err(e) = engine.memory.rename_session(&id, &name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response();
    }
    if engine.session.id == id {
        engine.session.name = name;
    }
    Json(state_json(
        &engine,
        state.tools_enabled,
        &state.guard_label,
        agent_on(&state),
    ))
    .into_response()
}

async fn api_session_delete(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let mut engine = state.engine.lock().await;
    if let Err(e) = engine.memory.delete_session(&id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response();
    }
    if engine.session.id == id {
        match engine
            .memory
            .list_sessions()
            .unwrap_or_default()
            .into_iter()
            .find(|info| info.message_count > 0)
        {
            Some(info) => {
                if let Ok(sess) = crate::core::session::Session::load(&engine.memory, &info.id) {
                    engine.session = sess;
                }
            }
            None => {
                if let Ok(sess) = crate::core::session::Session::create(&engine.memory, "chat") {
                    engine.session = sess;
                }
            }
        }
    }
    Json(state_json(
        &engine,
        state.tools_enabled,
        &state.guard_label,
        agent_on(&state),
    ))
    .into_response()
}

async fn api_session_new(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let name = body["name"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("chat")
        .to_string();
    let mut engine = state.engine.lock().await;
    match crate::core::session::Session::create(&engine.memory, &name) {
        Ok(sess) => {
            engine.session = sess;
            Json(state_json(
                &engine,
                state.tools_enabled,
                &state.guard_label,
                agent_on(&state),
            ))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_branch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let name = body["name"].as_str().unwrap_or("").trim().to_string();
    let from = body["from"].as_u64().map(|v| v as usize);
    let parent_req = body["parent"].as_str().unwrap_or("").trim().to_string();
    let mut engine = state.engine.lock().await;
    let parent = if parent_req.is_empty() {
        engine.session.id.clone()
    } else {
        match resolve_session(&engine, &parent_req) {
            Some(id) => id,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": format!("no session matches '{parent_req}'") })),
                )
                    .into_response()
            }
        }
    };
    let parent_msgs = crate::core::session::Session::load(&engine.memory, &parent)
        .map(|s| s.messages.len())
        .unwrap_or(0);
    let keep = from.unwrap_or(parent_msgs).min(parent_msgs);
    let parent_name = if parent == engine.session.id {
        engine.session.name.clone()
    } else {
        engine
            .memory
            .list_sessions()
            .unwrap_or_default()
            .into_iter()
            .find(|s| s.id == parent)
            .map(|s| s.name)
            .unwrap_or_else(|| "branch".to_string())
    };
    let name = if name.is_empty() {
        format!("{parent_name}~{parent_msgs}")
    } else {
        name
    };
    match crate::core::session::Session::fork(&engine.memory, &parent, &name, keep) {
        Ok(sess) => {
            engine.session = sess;
            Json(state_json(
                &engine,
                state.tools_enabled,
                &state.guard_label,
                agent_on(&state),
            ))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_model(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let model = body["model"].as_str().unwrap_or("").trim().to_string();
    if model.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "model is required" })),
        )
            .into_response();
    }
    {
        let mut engine = state.engine.lock().await;
        engine.model = model.clone();
    }
    // Persist best-effort so the choice survives a restart.
    if let Ok(paths) = crate::config::Paths::resolve() {
        if let Ok(mut s) = crate::config::Settings::load(&paths.config_file) {
            s.default_model = model;
            let _ = s.save(&paths.config_file);
        }
    }
    let engine = state.engine.lock().await;
    Json(state_json(
        &engine,
        state.tools_enabled,
        &state.guard_label,
        agent_on(&state),
    ))
    .into_response()
}

async fn api_toggle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let mut engine = state.engine.lock().await;
    if let Some(v) = body.get("air_gap").and_then(Value::as_bool) {
        engine.air_gap = v;
    }
    if let Some(v) = body.get("route_sensitive").and_then(Value::as_bool) {
        engine.route_sensitive = v;
    }
    if let Some(v) = body.get("plan").and_then(Value::as_bool) {
        engine.mode = if v {
            crate::core::engine::AgentMode::Plan
        } else {
            crate::core::engine::AgentMode::Build
        };
    }
    drop(engine);
    if let Some(v) = body.get("agent").and_then(Value::as_bool) {
        state.agent.store(v, Ordering::Relaxed);
    }
    let engine = state.engine.lock().await;
    Json(state_json(
        &engine,
        state.tools_enabled,
        &state.guard_label,
        agent_on(&state),
    ))
    .into_response()
}

async fn api_files(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let ws = {
        let engine = state.engine.lock().await;
        engine.workspace.clone()
    };
    let mut files = Vec::new();
    crate::cli::collect_files(&ws, &mut files, 0);
    let mut list: Vec<String> = files
        .iter()
        .filter_map(|p| p.strip_prefix(&ws).ok())
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    list.sort();
    list.truncate(5000);
    Json(json!({ "files": list })).into_response()
}

async fn api_search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let query = q.get("q").cloned().unwrap_or_default();
    if query.trim().is_empty() {
        return Json(json!({ "hits": [] })).into_response();
    }
    let engine = state.engine.lock().await;
    let hits = engine
        .memory
        .search_messages(&query, 100)
        .unwrap_or_default();
    Json(json!({
        "hits": hits.iter().map(|h| json!({
            "session_id": h.session_id,
            "session_name": h.session_name,
            "role": h.role,
            "snippet": h.snippet,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn api_graph(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let engine = state.engine.lock().await;
    let nodes = engine.memory.branch_nodes().unwrap_or_default();
    let current = engine.session.id.clone();
    Json(json!({
        "current": current,
        "nodes": nodes.iter().map(|n| json!({
            "id": n.id,
            "name": n.name,
            "parent": n.parent,
            "from": n.from,
            "message_count": n.message_count,
            "updated_at": n.updated_at,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

fn attachments_from(body: &Value) -> Vec<crate::core::attachment::Attachment> {
    body["attachments"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

async fn api_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let raw = q.get("path").cloned().unwrap_or_default();
    if raw.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "path is required" })),
        )
            .into_response();
    }
    let ws = {
        let engine = state.engine.lock().await;
        engine.workspace.clone()
    };
    let path = match crate::core::builtin_tools::resolve_in_workspace(&ws, &raw) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    };
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let mut c = content;
            if c.len() > 200_000 {
                c.truncate(200_000);
                c.push_str("\n… (truncated)");
            }
            Json(json!({ "path": raw, "content": c })).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_models(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let provider = {
        let engine = state.engine.lock().await;
        engine.provider_name().to_string()
    };
    let mut models: Vec<(String, String)> = Vec::new();
    if provider == "openrouter" {
        if let Some(key) = crate::privacy::SecureCredentials::local_api_key("openrouter") {
            if let Ok(list) = crate::providers::openrouter::OpenRouterModel::fetch_all().await {
                let _ = key;
                for m in list {
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
                    models.push((m.id, meta));
                }
            }
        }
    }
    if models.is_empty() {
        for id in crate::providers::suggested_models(&provider) {
            models.push((id.to_string(), "suggested".to_string()));
        }
    }
    Json(json!({
        "provider": provider,
        "models": models.iter().map(|(id, meta)| json!({ "id": id, "meta": meta })).collect::<Vec<_>>(),
    }))
    .into_response()
}

/// Stream an assistant reply as Server-Sent Events, then persist it.
async fn api_send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let text = body["text"].as_str().unwrap_or("").trim().to_string();
    if text.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "empty message" })),
        )
            .into_response();
    }
    let attachments = attachments_from(&body);

    let stream = {
        let mut engine = state.engine.lock().await;
        match engine.stream_reply_with(&text, attachments).await {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({ "error": e.to_string() })),
                )
                    .into_response();
            }
        }
    };

    let engine_arc = state.engine.clone();
    let body_stream = async_stream::stream! {
        let mut s = stream;
        let mut full = String::new();
        while let Some(item) = s.next().await {
            match item {
                Ok(chunk) => {
                    full.push_str(&chunk);
                    let data = serde_json::to_string(&chunk).unwrap_or_default();
                    yield Ok::<Bytes, std::convert::Infallible>(Bytes::from(format!(
                        "event: delta\ndata: {data}\n\n"
                    )));
                }
                Err(e) => {
                    let data = serde_json::to_string(&e.to_string()).unwrap_or_default();
                    yield Ok::<Bytes, std::convert::Infallible>(Bytes::from(format!(
                        "event: error\ndata: {data}\n\n"
                    )));
                    break;
                }
            }
        }
        {
            let mut engine = engine_arc.lock().await;
            let _ = engine.commit_assistant(full.clone());
        }
        let data = serde_json::to_string(&full).unwrap_or_default();
        yield Ok::<Bytes, std::convert::Infallible>(Bytes::from(format!(
            "event: done\ndata: {data}\n\n"
        )));
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .header("x-accel-buffering", "no")
        .body(Body::from_stream(body_stream))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn tool_context(
    engine: &ChatEngine,
    tools: &ToolsSettings,
) -> crate::core::builtin_tools::ToolContext {
    crate::core::builtin_tools::ToolContext {
        workspace: engine.workspace.clone(),
        shell_timeout_secs: tools.timeout_secs,
        max_output_bytes: tools.max_output_bytes,
        sandbox: Some(crate::core::tools::Sandbox::new(
            tools.sandbox,
            engine.workspace.clone(),
        )),
        todos: Some(engine.todos.clone()),
        mcp: engine.mcp.clone(),
        ..Default::default()
    }
}

fn pending_calls(engine: &ChatEngine) -> Option<Vec<ToolCall>> {
    match engine.session.messages.last() {
        Some(m) if m.role == crate::core::message::Role::Assistant && !m.tool_calls.is_empty() => {
            Some(m.tool_calls.clone())
        }
        _ => None,
    }
}

fn suggested(engine: &ChatEngine, call: &ToolCall) -> &'static str {
    match engine.effective_action(call) {
        Action::Allow => "approve",
        Action::Deny => "deny",
        Action::Ask => "ask",
    }
}

async fn execute_one(
    engine: &mut ChatEngine,
    ctx: &crate::core::builtin_tools::ToolContext,
    call: &ToolCall,
) -> Value {
    if let Some(res) = engine.execute_stateful(call) {
        let text = match res {
            Ok(t) => t,
            Err(e) => format!("[tool error] {e}"),
        };
        let _ = engine.push_tool_result(&call.id, &text);
        return json!({ "id": call.id, "name": call.name, "output": text });
    }
    let mut gate = crate::core::engine::ApprovedGate;
    match crate::core::builtin_tools::execute_detailed(call, ctx, &mut gate).await {
        Ok(out) => {
            let _ = engine.push_tool_result(&call.id, &out.text);
            let mut v = json!({ "id": call.id, "name": call.name, "output": out.text });
            if let Some(ch) = out.change {
                v["change"] = json!({ "path": ch.path, "added": ch.added, "removed": ch.removed });
            }
            v
        }
        Err(e) => {
            let m = format!("[tool error] {e}");
            let _ = engine.push_tool_result(&call.id, &m);
            json!({ "id": call.id, "name": call.name, "output": m })
        }
    }
}

/// Drive the agentic loop. `decisions` maps a tool-call id to "approve"/"deny";
/// calls whose permission is `ask` and have no decision are returned to the UI.
async fn agent_round(
    engine: &mut ChatEngine,
    tools: &ToolsSettings,
    decisions: &HashMap<String, String>,
) -> Value {
    let ctx = tool_context(engine, tools);
    let defs = engine.tool_defs(false);
    let (text, calls) = match pending_calls(engine) {
        Some(c) => (String::new(), c),
        None => match engine.agentic_step(&defs).await {
            Ok(AgentStep::Final(t)) => return json!({ "type": "final", "text": t }),
            Ok(AgentStep::ToolCalls { text, calls }) => (text, calls),
            Err(e) => return json!({ "type": "error", "error": e.to_string() }),
        },
    };
    let needs_ui = calls
        .iter()
        .any(|c| !decisions.contains_key(&c.id) && suggested(engine, c) == "ask");
    if needs_ui && decisions.is_empty() {
        let list: Vec<Value> = calls
            .iter()
            .map(|c| {
                json!({
                    "id": c.id, "name": c.name, "arguments": c.arguments,
                    "suggested": suggested(engine, c),
                })
            })
            .collect();
        return json!({ "type": "tools", "text": text, "calls": list, "results": [] });
    }
    let mut results = Vec::new();
    for call in &calls {
        let dec = decisions
            .get(&call.id)
            .map(String::as_str)
            .unwrap_or_else(|| suggested(engine, call));
        if dec == "approve" {
            results.push(execute_one(engine, &ctx, call).await);
        } else {
            let label = if dec == "deny" {
                "[denied by user]"
            } else {
                "[denied by policy]"
            };
            let _ = engine.push_tool_result(&call.id, label);
            results
                .push(json!({ "id": call.id, "name": call.name, "denied": true, "output": label }));
        }
    }
    json!({ "type": "tools", "text": text, "calls": [], "results": results, "continuing": true })
}

async fn api_agent_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let text = body["text"].as_str().unwrap_or("").trim().to_string();
    if text.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "empty message" })),
        )
            .into_response();
    }
    let mut engine = state.engine.lock().await;
    if let Err(e) = engine.begin_agentic_with(&text, attachments_from(&body)) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response();
    }
    let result = agent_round(&mut engine, &state.tools, &HashMap::new()).await;
    Json(json!({ "result": result, "state": state_json(&engine, state.tools_enabled, &state.guard_label, agent_on(&state)) }))
        .into_response()
}

async fn api_agent_resume(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let mut decisions: HashMap<String, String> = HashMap::new();
    if let Some(obj) = body["decisions"].as_object() {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                decisions.insert(k.clone(), s.to_string());
            }
        }
    }
    let mut engine = state.engine.lock().await;
    let result = agent_round(&mut engine, &state.tools, &decisions).await;
    Json(json!({ "result": result, "state": state_json(&engine, state.tools_enabled, &state.guard_label, agent_on(&state)) }))
        .into_response()
}

async fn api_effort(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let raw = body["effort"]
        .as_str()
        .unwrap_or("default")
        .trim()
        .to_lowercase();
    let value: Option<String> = match raw.as_str() {
        "default" | "off" | "none" | "" => None,
        other => Some(other.to_string()),
    };
    {
        let mut engine = state.engine.lock().await;
        engine.reasoning_effort = value.clone();
    }
    if let Ok(paths) = crate::config::Paths::resolve() {
        if let Ok(mut s) = crate::config::Settings::load(&paths.config_file) {
            s.reasoning_effort = value;
            let _ = s.save(&paths.config_file);
        }
    }
    let engine = state.engine.lock().await;
    Json(state_json(
        &engine,
        state.tools_enabled,
        &state.guard_label,
        agent_on(&state),
    ))
    .into_response()
}

async fn api_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let name = body["provider"].as_str().unwrap_or("").trim().to_string();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "provider is required" })),
        )
            .into_response();
    }
    {
        let mut engine = state.engine.lock().await;
        if let Err(e) = engine.set_provider(&name) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    }
    if let Ok(paths) = crate::config::Paths::resolve() {
        if let Ok(mut s) = crate::config::Settings::load(&paths.config_file) {
            s.default_provider = name;
            let _ = s.save(&paths.config_file);
        }
    }
    let engine = state.engine.lock().await;
    Json(state_json(
        &engine,
        state.tools_enabled,
        &state.guard_label,
        agent_on(&state),
    ))
    .into_response()
}

async fn api_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let op = body["op"].as_str().unwrap_or("").to_string();
    let mut engine = state.engine.lock().await;
    let out = match op.as_str() {
        "undo" => match engine.undo_last_turn() {
            Ok(t) => json!({ "op": "undo", "text": t }),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": e.to_string() })),
                )
                    .into_response()
            }
        },
        "retry" => match engine.retry_last() {
            Ok(t) => json!({ "op": "retry", "text": t }),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": e.to_string() })),
                )
                    .into_response()
            }
        },
        "compact" => match engine.compact().await {
            Ok(s) => json!({ "op": "compact", "summary": s, "chars": s.chars().count() }),
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({ "error": e.to_string() })),
                )
                    .into_response()
            }
        },
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "unknown op" })),
            )
                .into_response()
        }
    };
    Json(json!({ "result": out, "state": state_json(&engine, state.tools_enabled, &state.guard_label, agent_on(&state)) }))
        .into_response()
}

fn resolve_session(engine: &ChatEngine, key: &str) -> Option<String> {
    let sessions = engine.memory.list_sessions().unwrap_or_default();
    sessions
        .iter()
        .find(|s| s.id == key)
        .or_else(|| sessions.iter().find(|s| s.id.starts_with(key)))
        .or_else(|| sessions.iter().find(|s| s.name == key))
        .map(|s| s.id.clone())
}

async fn api_checkout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let key = body["id"].as_str().unwrap_or("").trim().to_string();
    let mut engine = state.engine.lock().await;
    let id = match resolve_session(&engine, &key) {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("no session matches '{key}'") })),
            )
                .into_response()
        }
    };
    match crate::core::session::Session::load(&engine.memory, &id) {
        Ok(sess) => {
            engine.session = sess;
            Json(state_json(
                &engine,
                state.tools_enabled,
                &state.guard_label,
                agent_on(&state),
            ))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_merge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let key = body["source"].as_str().unwrap_or("").trim().to_string();
    let mut engine = state.engine.lock().await;
    let id = match resolve_session(&engine, &key) {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("no branch matches '{key}'") })),
            )
                .into_response()
        }
    };
    if id == engine.session.id {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "cannot merge a branch into itself" })),
        )
            .into_response();
    }
    let ChatEngine {
        session, memory, ..
    } = &mut *engine;
    match session.merge_from(memory, &id) {
        Ok(n) => Json(json!({
            "merged": n,
            "state": state_json(&engine, state.tools_enabled, &state.guard_label, agent_on(&state)),
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_init(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(_body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let mut engine = state.engine.lock().await;
    let ws = engine.workspace.clone();
    let path = ws.join("AGENTS.md");
    if path.exists() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "AGENTS.md already exists" })),
        )
            .into_response();
    }
    let mut files = Vec::new();
    crate::cli::collect_files(&ws, &mut files, 0);
    let list = files
        .iter()
        .take(200)
        .map(|p| p.strip_prefix(&ws).unwrap_or(p).display().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let mut ctx = String::new();
    for f in ["README.md", "Cargo.toml", "package.json", "pyproject.toml"] {
        if let Ok(t) = std::fs::read_to_string(ws.join(f)) {
            let head: String = t.chars().take(3000).collect();
            ctx.push_str(&format!("\n\n=== {f} ===\n{head}"));
        }
    }
    let prompt = format!(
        "Write an AGENTS.md file for this software project. Describe the build/verify commands, \
         repo layout, coding conventions and anything a new contributor must know. Reply with the \
         file content only, no code fences.\n\nProject files:\n{list}{ctx}"
    );
    match engine.one_shot(&prompt).await {
        Ok(text) => {
            let body = strip_fence(&text);
            match std::fs::write(&path, body) {
                Ok(()) => Json(json!({ "path": path.display().to_string() })).into_response(),
                Err(e) => (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": e.to_string() })),
                )
                    .into_response(),
            }
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

fn strip_fence(text: &str) -> String {
    let t = text.trim();
    let t = if t.starts_with("```") {
        t.split_once('\n').map(|x| x.1).unwrap_or("")
    } else {
        t
    };
    let t = t.trim_end();
    let t = t.strip_suffix("```").unwrap_or(t);
    t.trim().to_string()
}

async fn api_diff(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let a_key = q.get("a").cloned().unwrap_or_default();
    let b_key = q.get("b").cloned().unwrap_or_default();
    let engine = state.engine.lock().await;
    let (a_id, b_id) = match (
        resolve_session(&engine, &a_key),
        resolve_session(&engine, &b_key),
    ) {
        (Some(a), Some(b)) => (a, b),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "session not found" })),
            )
                .into_response()
        }
    };
    let a = engine
        .memory
        .get_history(&a_id, 100_000)
        .unwrap_or_default();
    let b = engine
        .memory
        .get_history(&b_id, 100_000)
        .unwrap_or_default();
    let ta = a
        .iter()
        .map(|m| m.content.clone())
        .collect::<Vec<_>>()
        .join("\n");
    let tb = b
        .iter()
        .map(|m| m.content.clone())
        .collect::<Vec<_>>()
        .join("\n");
    let lines = crate::core::diff::lines(&ta, &tb);
    let (added, removed) = crate::core::diff::stats(&lines);
    Json(json!({
        "a": a_key, "b": b_key, "added": added, "removed": removed,
        "lines": lines.iter().map(|l| json!({
            "kind": match l.kind {
                crate::core::diff::DiffKind::Add => "add",
                crate::core::diff::DiffKind::Remove => "remove",
                crate::core::diff::DiffKind::Context => "context",
            },
            "text": l.text,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn api_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let text = body["text"].as_str().unwrap_or("");
    let findings = crate::privacy::guard::scan(text);
    Json(json!({
        "findings": findings.iter().map(|f| json!({
            "kind": f.kind.label(),
            "text": f.text,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn api_memories(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let query = q.get("q").cloned().unwrap_or_default();
    let engine = state.engine.lock().await;
    let mems = if query.trim().is_empty() {
        engine.memory.list_memories(200).unwrap_or_default()
    } else {
        engine
            .memory
            .search_memories(&query, 200)
            .unwrap_or_default()
    };
    Json(json!({ "memories": mems.iter().map(|m| json!({
        "id": m.id, "text": m.text, "tags": m.tags, "kind": m.kind,
        "pinned": m.pinned, "local_only": m.local_only, "updated_at": m.updated_at,
    })).collect::<Vec<_>>() }))
    .into_response()
}

async fn api_memory_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let text = body["text"].as_str().unwrap_or("").trim().to_string();
    if text.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "text is required" })),
        )
            .into_response();
    }
    let tags = body["tags"].as_str().unwrap_or("").to_string();
    let local_only = body["local_only"].as_bool().unwrap_or(false);
    let engine = state.engine.lock().await;
    match engine
        .memory
        .add_memory(&text, &tags, "note", Some(&engine.session.id), local_only)
    {
        Ok(id) => Json(json!({ "id": id, "ok": true })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_memory_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let id = body["id"].as_str().unwrap_or("").trim().to_string();
    if id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "id is required" })),
        )
            .into_response();
    }
    let engine = state.engine.lock().await;
    match engine.memory.delete_memory(&id) {
        Ok(ok) => Json(json!({ "ok": ok })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_decisions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let query = q.get("q").cloned().unwrap_or_default();
    let engine = state.engine.lock().await;
    let ds = if query.trim().is_empty() {
        engine.memory.list_decisions(200).unwrap_or_default()
    } else {
        engine
            .memory
            .search_decisions(&query, 200)
            .unwrap_or_default()
    };
    Json(json!({ "decisions": ds.iter().map(|d| json!({
        "id": d.id, "session_id": d.session_id, "title": d.title, "body": d.body,
        "status": d.status, "tags": d.tags, "updated_at": d.updated_at,
    })).collect::<Vec<_>>() }))
    .into_response()
}

async fn api_decision_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let title = body["title"].as_str().unwrap_or("").trim().to_string();
    if title.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "title is required" })),
        )
            .into_response();
    }
    let rationale = body["body"].as_str().unwrap_or("").to_string();
    let tags = body["tags"].as_str().unwrap_or("").to_string();
    let status = body["status"].as_str().unwrap_or("accepted").to_string();
    let engine = state.engine.lock().await;
    match engine
        .memory
        .add_decision(Some(&engine.session.id), &title, &rationale, &tags, &status)
    {
        Ok(id) => Json(json!({ "id": id, "ok": true })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_decision_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let id = body["id"].as_str().unwrap_or("").trim().to_string();
    if id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "id is required" })),
        )
            .into_response();
    }
    let engine = state.engine.lock().await;
    match engine.memory.delete_decision(&id) {
        Ok(ok) => Json(json!({ "ok": ok })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_context(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let engine = state.engine.lock().await;
    let r = engine.context_report();
    Json(json!({
        "provider": r.provider,
        "model": r.model,
        "mode": r.mode,
        "parts": r.parts.iter().map(|p| json!({
            "label": p.label, "detail": p.detail, "chars": p.chars
        })).collect::<Vec<_>>(),
        "messages": r.messages,
        "history_chars": r.history_chars,
        "redactions": r.redactions,
        "taint": r.taint,
        "total_chars": r.total_chars,
        "est_tokens": r.est_tokens,
        "limit_tokens": r.limit_tokens,
        "warn_pct": r.warn_pct,
    }))
    .into_response()
}

async fn api_exposure(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    use crate::config::SandboxMode;
    use crate::privacy::exposure::{blast_radius, privacy_score, ScoreInputs};

    let engine = state.engine.lock().await;
    let summary = engine.memory.egress_summary(None).unwrap_or_default();
    let br = blast_radius(&summary);
    let redactions: i64 = summary.kinds.iter().map(|(_, c)| *c).sum();
    let local_only_memories = engine
        .memory
        .list_memories(1000)
        .unwrap_or_default()
        .iter()
        .filter(|m| m.local_only)
        .count() as i64;
    let inputs = ScoreInputs {
        remote: br.remote,
        local: br.local,
        redactions,
        air_gap: engine.air_gap,
        route_sensitive: engine.route_sensitive,
        guard_enabled: state.guard_label != "off",
        taint: engine.taint,
        sandbox_on: state.tools.sandbox != SandboxMode::Off,
        anonymised_network: false,
        local_only_memories,
    };
    let score = privacy_score(&inputs);
    Json(json!({
        "blast_radius": {
            "total": br.total, "remote": br.remote, "local": br.local,
            "redacted": br.redacted, "bytes": br.bytes,
            "providers": br.providers.iter().map(|(n, c)| json!({ "name": n, "count": c })).collect::<Vec<_>>(),
            "kinds": br.kinds.iter().map(|(n, c)| json!({ "name": n, "count": c })).collect::<Vec<_>>(),
        },
        "score": { "score": score.score, "grade": score.grade,
            "factors": score.factors.iter().map(|(l, d)| json!({ "label": l, "delta": d })).collect::<Vec<_>>() },
    }))
    .into_response()
}

async fn api_ledger(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let verify = q
        .get("verify")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    let per_session = q
        .get("session")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    let engine = state.engine.lock().await;
    let entries = if per_session {
        engine
            .memory
            .list_egress_for_session(&engine.session.id, 100)
            .unwrap_or_default()
    } else {
        engine.memory.list_egress(100).unwrap_or_default()
    };
    let count = engine.memory.egress_count().unwrap_or(0);
    let chain_ok = if verify {
        Some(engine.memory.verify_egress_chain().unwrap_or(false))
    } else {
        None
    };
    Json(json!({
        "count": count,
        "chain_ok": chain_ok,
        "entries": entries.iter().map(|e| json!({
            "id": e.id, "ts": e.ts, "provider": e.provider, "model": e.model,
            "payload_sha": e.payload_sha, "payload_bytes": e.payload_bytes,
            "redactions": e.redactions, "original_sha": e.original_sha,
            "session_id": e.session_id,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn api_rag(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let op = body["op"].as_str().unwrap_or("status");
    let engine = state.engine.lock().await;
    match op {
        "search" => {
            let query = body["q"].as_str().unwrap_or("").trim().to_string();
            let limit = body["limit"].as_u64().unwrap_or(6) as usize;
            let chunks = engine.memory.all_rag_chunks().unwrap_or_default();
            let readable: Vec<crate::privacy::RagChunk> = chunks
                .into_iter()
                .filter(|c| crate::core::rag::is_readable(std::path::Path::new(&c.source)))
                .collect();
            let hits = crate::core::rag::keyword_search(&query, &readable, limit);
            Json(json!({ "hits": hits.iter().map(|h| json!({
                "source": h.source, "score": h.score, "text": h.text,
            })).collect::<Vec<_>>() }))
            .into_response()
        }
        "index" => {
            let mut files = Vec::new();
            if let Some(paths) = body["paths"].as_array() {
                for p in paths {
                    if let Some(s) = p.as_str() {
                        crate::cli::collect_files(std::path::Path::new(s), &mut files, 0);
                    }
                }
            }
            let replace = body["replace"].as_bool().unwrap_or(false);
            let mut total = 0usize;
            let mut nfiles = 0usize;
            for file in &files {
                let source = file.display().to_string();
                let text = match std::fs::read(file)
                    .ok()
                    .and_then(|d| String::from_utf8(d).ok())
                {
                    Some(t) if !t.trim().is_empty() => t,
                    _ => continue,
                };
                if replace {
                    let _ = engine.memory.clear_rag_source(&source);
                }
                let chunks = crate::core::rag::chunk_text(&text, 1200);
                for (i, chunk) in chunks.iter().enumerate() {
                    let _ = engine.memory.add_rag_chunk(&source, i as i64, chunk, None);
                    total += 1;
                }
                nfiles += 1;
            }
            Json(json!({ "files": nfiles, "chunks": total })).into_response()
        }
        "clear" => {
            let n = engine.memory.clear_rag().unwrap_or(0);
            Json(json!({ "cleared": n })).into_response()
        }
        _ => {
            let sources = engine.memory.rag_sources().unwrap_or_default();
            let count = engine.memory.rag_count().unwrap_or(0);
            Json(json!({
                "count": count,
                "sources": sources.iter().map(|(s, n)| json!({ "source": s, "chunks": n })).collect::<Vec<_>>(),
            }))
            .into_response()
        }
    }
}

async fn api_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let fmt = body["format"].as_str().unwrap_or("html").to_lowercase();
    let engine = state.engine.lock().await;
    let name = engine.session.name.clone();
    let model = engine.model.clone();
    let messages = engine.session.messages.clone();
    let (bytes, mime, ext): (Vec<u8>, &str, &str) = match fmt.as_str() {
        "md" | "markdown" => (
            crate::core::export::render_markdown(&name, &model, &messages).into_bytes(),
            "text/markdown; charset=utf-8",
            "md",
        ),
        "pdf" => (
            crate::core::export::render_pdf(&name, &model, &messages),
            "application/pdf",
            "pdf",
        ),
        _ => (
            crate::core::export::render_html(&name, &model, &messages).into_bytes(),
            "text/html; charset=utf-8",
            "html",
        ),
    };
    let filename = format!(
        "enclave-{}.{}",
        &engine.session.id[..8.min(engine.session.id.len())],
        ext
    );
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", mime)
        .header(
            "content-disposition",
            format!("attachment; filename=\"{filename}\""),
        )
        .body(Body::from(bytes))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

async fn api_shell(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &q) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let cmd = body["cmd"].as_str().unwrap_or("").trim().to_string();
    if cmd.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "cmd is required" })),
        )
            .into_response();
    }
    let (timeout, cap, mode, ws) = {
        let engine = state.engine.lock().await;
        (
            state.tools.timeout_secs,
            state.tools.max_output_bytes,
            state.tools.sandbox,
            engine.workspace.clone(),
        )
    };
    let sandbox = crate::core::tools::Sandbox::new(mode, ws);
    match crate::core::tools::run_sandboxed(
        &cmd,
        std::time::Duration::from_secs(timeout),
        cap,
        Some(&sandbox),
    )
    .await
    {
        Ok(out) => Json(json!({ "output": out.render() })).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

const INDEX_HTML: &str = r#"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>enclave — local</title>
<style>
  body[data-theme="default"]{--bg:#111216;--surface:#1e1f25;--surface-hi:#2c2e36;--text:#e2e2e8;--dim:#848694;--accent:#a78bfa;--green:#86efac;--red:#f89696;--yellow:#fadc78;--line:rgba(255,255,255,.06);}
  body[data-theme="nord"]{--bg:#2e3440;--surface:#3b4252;--surface-hi:#434c5e;--text:#eceff4;--dim:#81a1c1;--accent:#88c0d0;--green:#a3be8c;--red:#bf616a;--yellow:#ebcb8b;--line:rgba(255,255,255,.07);}
  body[data-theme="gruvbox"]{--bg:#282828;--surface:#3c3836;--surface-hi:#504945;--text:#ebdbb2;--dim:#928374;--accent:#fabd2f;--green:#b8bb26;--red:#fb4934;--yellow:#fabd2f;--line:rgba(255,255,255,.07);}
  body[data-theme="solarized"]{--bg:#002b36;--surface:#073642;--surface-hi:#586e75;--text:#eee8d5;--dim:#839496;--accent:#268bd2;--green:#859900;--red:#dc322f;--yellow:#b58900;--line:rgba(255,255,255,.08);}
  body[data-theme="mono"]{--bg:#0c0c0c;--surface:#181818;--surface-hi:#282828;--text:#e0e0e0;--dim:#808080;--accent:#c0c0c0;--green:#c8c8c8;--red:#a0a0a0;--yellow:#b4b4b4;--line:rgba(255,255,255,.08);}
  *{box-sizing:border-box;}
  html,body{margin:0;height:100%;}
  body{display:flex;flex-direction:column;height:100vh;overflow:hidden;background:var(--bg);color:var(--text);
       font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
  ::-webkit-scrollbar{width:10px;height:10px;}
  ::-webkit-scrollbar-thumb{background:var(--surface-hi);border-radius:8px;border:2px solid transparent;background-clip:content-box;}
  ::-webkit-scrollbar-thumb:hover{background:var(--dim);background-clip:content-box;}
  ::-webkit-scrollbar-track{background:transparent;}
  .mono{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;}
  button.btn{background:var(--surface-hi);color:var(--text);border:0;border-radius:7px;padding:6px 12px;font:inherit;font-size:13px;cursor:pointer;}
  button.btn:hover{filter:brightness(1.15);}
  button.btn.primary{background:var(--accent);color:var(--bg);font-weight:600;}
  button.btn.danger{background:rgba(248,150,150,.18);color:var(--red);}
  input.minput,.ovfilter{width:100%;background:var(--bg);color:var(--text);border:1px solid var(--line);
       border-radius:7px;padding:8px 10px;font:inherit;outline:0;}
  input.minput:focus,.ovfilter:focus{border-color:var(--accent);}

  header.bar{flex:0 0 auto;display:flex;align-items:center;justify-content:space-between;
             padding:7px 14px;background:var(--surface);border-bottom:1px solid var(--line);}
  header .brand{display:flex;align-items:baseline;gap:8px;}
  header .brand .d{color:var(--accent);}
  header .brand b{color:var(--text);font-weight:700;}
  header .meta{color:var(--dim);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:62%;}
  header .meta .pill{display:inline-block;padding:0 7px;border-radius:5px;background:var(--surface-hi);color:var(--text);font-size:11px;margin-left:6px;}
  header .meta .pill.plan{background:var(--yellow);color:var(--bg);}
  .dimtxt{color:var(--dim);}
  .hbtn{background:transparent;border:1px solid var(--line);color:var(--dim);border-radius:6px;cursor:pointer;
        font:inherit;font-size:12px;padding:1px 7px;margin-left:6px;line-height:1.4;transition:color .12s,border-color .12s,background .12s;}
  .hbtn:hover{color:var(--text);border-color:var(--accent);}
  .hbtn.off{opacity:.45;}
  header .meta .pill{cursor:pointer;transition:filter .12s,opacity .12s,background .12s;}
  header .meta .pill:hover{filter:brightness(1.15);}
  header .meta .pill.off{background:transparent;border:1px solid var(--line);color:var(--dim);}
  header .meta .pill.on{background:var(--accent);color:var(--bg);}
  header .meta .pill.on.plan{background:var(--yellow);}
  body.noside aside.side{display:none;}
  body.noinfo aside.info{display:none;}
  body.showside aside.side{display:flex !important;}
  body.showinfo aside.info{display:flex !important;}
  .jumpbtn{position:fixed;right:24px;bottom:112px;z-index:40;background:var(--accent);color:var(--bg);border:0;
           border-radius:999px;padding:6px 13px;font:inherit;font-size:12px;font-weight:600;cursor:pointer;
           box-shadow:0 8px 24px rgba(0,0,0,.45);}
  .jumpbtn:hover{filter:brightness(1.1);}

  main{flex:1 1 auto;display:flex;min-height:0;}
  aside{background:var(--surface);overflow-y:auto;flex:0 0 auto;display:flex;flex-direction:column;}
  aside.side{width:258px;border-right:1px solid var(--line);}
  aside.info{width:306px;border-left:1px solid var(--line);padding:12px 14px;}
  .sidehead{padding:10px 12px 6px;display:flex;flex-direction:column;gap:8px;}
  .sidehead .titlerow{display:flex;justify-content:space-between;align-items:center;}
  .sidehead h2{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);font-weight:700;margin:0;}
  .sidehead .add{color:var(--dim);cursor:pointer;font-size:12px;padding:2px 8px;border-radius:6px;background:var(--surface-hi);}
  .sidehead .add:hover{color:var(--bg);background:var(--accent);}
  .sesslist{flex:1 1 auto;overflow-y:auto;padding:4px 8px 12px;}
  .sess{display:flex;align-items:center;gap:8px;padding:7px 10px;border-radius:8px;cursor:pointer;
        color:var(--dim);font-size:13px;position:relative;}
  .sess:hover{background:var(--surface-hi);color:var(--text);}
  .sess.active{color:var(--text);font-weight:600;background:rgba(167,139,250,.10);}
  .sess .b{color:var(--accent);flex:0 0 auto;}
  .sess .nm{flex:1 1 auto;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
  .sess .n{color:var(--dim);font-size:11px;flex:0 0 auto;}
  .sess .acts{position:absolute;right:6px;display:none;gap:2px;background:var(--surface-hi);border-radius:6px;padding:1px;}
  .sess:hover .acts{display:flex;}
  .sess .acts span{padding:2px 6px;border-radius:5px;color:var(--dim);font-size:12px;}
  .sess .acts span:hover{background:var(--bg);color:var(--text);}
  .sess .acts span.del:hover{color:var(--red);}

  section.chat{flex:1 1 auto;overflow-y:auto;background:var(--bg);padding:26px 30px;display:flex;flex-direction:column;gap:12px;}
  .card{border-radius:10px;padding:11px 15px;position:relative;transition:box-shadow .16s ease,transform .16s ease;}
  .card.user:hover,.card.assistant:hover{box-shadow:0 6px 22px rgba(0,0,0,.28);}
  .copybtn{position:absolute;top:6px;right:8px;opacity:0;cursor:pointer;color:var(--dim);font-size:13px;
           padding:2px 6px;border-radius:5px;transition:opacity .12s;user-select:none;}
  .card:hover .copybtn{opacity:1;}
  .copybtn:hover{background:var(--surface-hi);color:var(--text);}
  .card.user{align-self:flex-end;max-width:82%;background:var(--surface-hi);border-left:0;border-right:3px solid var(--accent);border-radius:13px 13px 4px 13px;}
  .card.assistant{align-self:stretch;background:var(--surface);border-left:3px solid var(--surface-hi);}
  .card.system{background:transparent;color:var(--dim);font-style:italic;font-size:13px;border-left:3px solid transparent;}
  .card.tool{background:transparent;border-left:3px solid transparent;font-size:13px;}
  .att{display:inline-flex;align-items:center;gap:6px;margin:6px 6px 0 0;padding:3px 8px;border-radius:6px;
       background:rgba(255,255,255,.05);color:var(--dim);font-size:12px;}
  .att img{max-width:220px;max-height:160px;border-radius:6px;display:block;}
  .badge{display:inline-block;margin-left:8px;padding:1px 6px;border-radius:5px;font-size:10px;letter-spacing:.08em;
         text-transform:uppercase;background:rgba(248,150,150,.14);color:var(--red);}
  .tool-line{white-space:pre-wrap;word-break:break-word;}
  .card.tool .hdr{color:var(--yellow);font-weight:600;font-family:ui-monospace,Menlo,monospace;font-size:12.5px;}
  body.hidetools .card.tool{display:none;}
  .tl-add{color:var(--green);}
  .tl-del{color:var(--red);}
  .tl-meta{color:var(--dim);}
  .tl-def{color:var(--yellow);}
  .approve{background:var(--surface-hi);border-left:3px solid var(--yellow);border-radius:10px;padding:11px 15px;}
  .approve .hdr{color:var(--yellow);font-weight:700;font-size:12.5px;letter-spacing:.03em;}
  .approve .cmd{font-family:ui-monospace,Menlo,monospace;color:var(--text);white-space:pre-wrap;word-break:break-word;
                font-size:12.5px;margin:6px 0 10px;background:rgba(0,0,0,.18);padding:8px 10px;border-radius:7px;}
  .approve .row{display:flex;gap:8px;align-items:center;}
  .approve .row .hint{color:var(--dim);font-size:11.5px;margin-left:4px;}
  .diffsec{font-family:ui-monospace,Menlo,monospace;font-size:12.5px;white-space:pre-wrap;word-break:break-word;}
  .diffsec .add{color:var(--green);}
  .diffsec .del{color:var(--red);}
  .diffsec .ctx{color:var(--dim);}
  header .meta .pill.agent{background:var(--accent);color:var(--bg);}
  .welcome{max-width:840px;}
  .welcome h1{color:var(--accent);font-size:18px;margin:4px 0 2px;}
  .welcome .sub{color:var(--dim);font-size:13px;}
  .welcome h3{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--text);margin:16px 0 6px;}
  .welcome .row{display:flex;gap:10px;font-size:13px;}
  .welcome .row .k{color:var(--accent);font-weight:700;min-width:96px;}
  .welcome .row .d{color:var(--dim);}
  .empty{color:var(--dim);margin:auto;font-size:13px;}
  .md h1{font-size:17px;color:#9ae0ff;margin:10px 0 4px;}
  .md h2,.md h3{font-size:14px;color:#7ab6ff;margin:10px 0 4px;}
  .md p{margin:6px 0;}
  .md code{color:var(--yellow);background:rgba(255,255,255,.05);padding:0 4px;border-radius:4px;}
  .md pre{white-space:pre-wrap;word-break:break-word;margin:4px 0;font-size:13px;
          font-family:ui-monospace,SFMono-Regular,Menlo,monospace;}
  .md .gutter{color:#555;user-select:none;}
  .md .code{color:#5fd0d0;}
  .md blockquote{margin:6px 0;color:#aaa;font-style:italic;}
  .codewin{border:1px solid var(--line);border-radius:10px;overflow:hidden;margin:9px 0;background:#0c0d11;}
  .cwhead{display:flex;align-items:center;gap:9px;padding:5px 11px;background:var(--surface-hi);font-size:11.5px;
          color:var(--dim);font-family:ui-monospace,Menlo,monospace;}
  .cwhead .lang{color:var(--accent);font-weight:700;}
  .cwhead .stats{color:var(--dim);}
  .cwhead .cadd{color:var(--green);}
  .cwhead .cdel{color:var(--red);}
  .cwhead .cp{margin-left:auto;cursor:pointer;padding:1px 8px;border-radius:6px;user-select:none;}
  .cwhead .cp:hover{background:var(--bg);color:var(--text);}
  .codegrid{overflow-x:auto;padding:7px 0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;line-height:1.5;}
  .crow{display:grid;grid-template-columns:auto 1fr;}
  .crow .ln{color:#4a4d5a;text-align:right;padding:0 11px 0 13px;user-select:none;}
  .crow .lc{white-space:pre;padding-right:16px;color:#5fd0d0;}
  .splitdiff{display:grid;grid-template-columns:1fr 1fr;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
             font-size:12.5px;line-height:1.5;}
  .splitdiff .pane{overflow-x:auto;padding:7px 0;}
  .splitdiff .pane.right{border-left:1px solid var(--line);}
  .splitdiff .phead{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--dim);padding:0 13px 4px;}
  .drow{display:grid;grid-template-columns:auto 1fr;}
  .drow .ln{color:#4a4d5a;text-align:right;padding:0 10px 0 13px;user-select:none;}
  .drow .lc{white-space:pre;padding-right:14px;color:var(--text);}
  .drow.ctx .lc{color:var(--dim);}
  .drow.add{background:rgba(134,239,172,.12);} .drow.add .lc{color:var(--green);}
  .drow.del{background:rgba(248,150,150,.12);} .drow.del .lc{color:var(--red);}
  .drow.mod{background:rgba(250,220,120,.07);}
  .drow.empty .lc{color:transparent;}
  .drow.sep .lc{color:var(--accent);opacity:.7;}

  .toolbar{flex:0 0 auto;background:var(--surface);display:flex;gap:6px;padding:7px 14px 2px;flex-wrap:wrap;}
  .tb{cursor:pointer;color:var(--dim);border:1px solid var(--line);border-radius:999px;padding:2px 11px;font-size:12px;white-space:nowrap;transition:border-color .1s,color .1s;}
  .tb:hover{border-color:var(--accent);color:var(--text);}
  .tb.on{border-color:var(--accent);color:var(--accent);}
  .gactions{display:flex;gap:6px;flex-wrap:wrap;padding:2px 16px 10px;}
  .gbtn{cursor:pointer;color:var(--text);background:var(--surface-hi);border:1px solid var(--line);border-radius:8px;padding:4px 12px;font-size:12.5px;}
  .gbtn:hover{border-color:var(--accent);color:var(--accent);}
  .gbtn.danger:hover{border-color:var(--red);color:var(--red);}
  .gsel{margin-left:auto;color:var(--dim);font-size:12px;align-self:center;font-family:ui-monospace,Menlo,monospace;}
  .gnode.sel rect{stroke:var(--accent);stroke-width:2.5;}
  .composer{flex:0 0 auto;background:var(--surface);border:1px solid var(--line);border-left:3px solid var(--accent);
            border-radius:13px;display:flex;gap:10px;padding:11px 13px;flex-wrap:wrap;margin-top:8px;
            transition:border-color .15s,box-shadow .15s;box-shadow:0 4px 18px rgba(0,0,0,.22);}
  .composer:focus-within{border-color:var(--accent);box-shadow:0 8px 28px rgba(0,0,0,.34);}
  .composer.plan{border-left-color:var(--yellow);}
  .composer.agent{border-left-color:var(--accent);}
  .composer .prompt{color:var(--accent);font-weight:700;flex:0 0 auto;padding-top:2px;}
  .composer .clip{color:var(--dim);cursor:pointer;flex:0 0 auto;padding:2px 8px;border-radius:6px;font-size:15px;}
  .composer .clip:hover{background:var(--surface-hi);color:var(--text);}
  .composer .send{cursor:pointer;flex:0 0 auto;background:var(--accent);color:var(--bg);font-weight:700;
                  border:0;border-radius:8px;padding:4px 12px;font-size:12.5px;align-self:flex-start;}
  .composer .send:hover{filter:brightness(1.1);}
  .attchips{width:100%;display:flex;gap:6px;flex-wrap:wrap;}
  .attchips:empty{display:none;}
  textarea{flex:1 1 auto;resize:none;background:transparent;border:0;outline:0;color:var(--text);
           font:14px/1.5 inherit;min-height:22px;max-height:180px;}
  textarea::placeholder{color:var(--dim);}
  .privacy{flex:0 0 auto;padding:3px 14px;background:var(--bg);color:var(--dim);font-size:11px;
           white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
  footer.bar{flex:0 0 auto;display:flex;align-items:center;justify-content:space-between;
             padding:6px 14px;background:var(--surface);border-top:1px solid var(--line);font-size:12px;gap:12px;}
  .chip{display:inline-block;padding:1px 8px;margin-right:8px;border-radius:5px;background:var(--surface-hi);
        color:var(--text);font-weight:600;font-size:11px;}
  .chip.model{background:var(--accent);color:var(--bg);cursor:pointer;}
  .chip.agentchip{cursor:pointer;background:var(--surface-hi);color:var(--dim);}
  .chip.agentchip.on{background:var(--accent);color:var(--bg);}
  .foot-status{color:var(--dim);}
  .foot-status.error{color:var(--red);}
  .foot-status.warn{color:var(--yellow);font-weight:600;}
  .foot-hint{color:var(--dim);white-space:nowrap;}
  .foot-hint .k{display:inline-block;background:var(--surface-hi);color:var(--text);padding:0 6px;border-radius:4px;margin-left:8px;}

  .info .row{display:flex;gap:10px;font-size:12.5px;margin:2px 0;}
  .info .row .k{color:var(--dim);min-width:66px;flex:0 0 auto;}
  .info .row .v{color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
  .info .row .v.accent{color:var(--accent);}
  .info .row .v.warn{color:var(--yellow);}
  .info .row .v.ok{color:var(--green);}
  .info .sec{margin-top:14px;color:var(--dim);font-weight:700;font-size:11px;letter-spacing:.12em;text-transform:uppercase;}

  .overlay{position:fixed;inset:0;display:flex;align-items:flex-start;justify-content:center;
           padding-top:11vh;background:rgba(0,0,0,.42);z-index:50;}
  .overlay .box,.overlay .modal{background:var(--surface-hi);border-left:3px solid var(--accent);border-radius:11px;
                box-shadow:0 24px 70px rgba(0,0,0,.55);}
  .overlay .box{width:min(600px,92vw);max-height:72vh;display:flex;flex-direction:column;padding:12px 0 6px;}
  .overlay .modal{width:min(460px,92vw);padding:16px 18px;display:flex;flex-direction:column;gap:10px;}
  .overlay .title{padding:2px 16px 10px;color:var(--accent);font-weight:700;font-size:12px;letter-spacing:.06em;}
  .overlay .mlab{color:var(--dim);font-size:12.5px;}
  .overlay .mbtns{display:flex;justify-content:flex-end;gap:8px;margin-top:2px;}
  .ovlist{overflow-y:auto;flex:1 1 auto;padding:0 0 4px;}
  .ovrow{display:flex;align-items:center;gap:12px;padding:7px 16px;font-size:13px;cursor:pointer;color:var(--text);}
  .ovrow .c{color:var(--accent);font-weight:600;min-width:104px;}
  .ovrow .d{color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1 1 auto;}
  .ovrow .ra{margin-left:auto;display:flex;gap:2px;}
  .ovrow .ra span{padding:1px 7px;border-radius:5px;color:var(--dim);font-size:12px;}
  .ovrow .ra span:hover{background:var(--bg);color:var(--text);}
  .ovrow.sel{background:var(--accent);color:var(--bg);}
  .ovrow.sel .c,.ovrow.sel .d,.ovrow.sel .ra span{color:var(--bg);}
  .ovrow.cur .c{color:var(--green);}
  .ovrow.cur.sel .c{color:var(--bg);}
  .ovempty{padding:14px 16px;color:var(--dim);font-size:13px;}
  .ovhint{padding:8px 16px 4px;color:var(--dim);font-size:11px;border-top:1px solid var(--line);margin-top:4px;}

  .overlay .graphbox{width:min(1180px,96vw);max-height:88vh;padding:12px 0 8px;}
  .overlay .graphbox .gscroll{overflow:auto;flex:1 1 auto;padding:4px 16px 10px;}
  .legend{color:var(--dim);font-size:11px;padding:0 0 10px;}
  .legend b{color:var(--text);font-weight:600;}
  .graphsvg{display:block;}
  .gnode{cursor:pointer;}
  .gnode rect{fill:var(--surface);stroke:var(--line);stroke-width:1.5;}
  .gnode:hover rect{stroke:var(--accent);}
  .gnode.cur rect{fill:var(--accent);stroke:var(--accent);}
  .gnode text{fill:var(--text);font:600 12px ui-monospace,SFMono-Regular,Menlo,monospace;}
  .gnode .sub{fill:var(--dim);font-weight:400;font-size:10.5px;}
  .gnode.cur text{fill:var(--bg);}
  .gnode.cur .sub{fill:var(--bg);opacity:.85;}
  .gedge{fill:none;stroke:var(--line);stroke-width:1.5;}
  .gedge.cur{stroke:var(--accent);}
  .glabel{fill:var(--dim);font-size:10px;font-family:ui-monospace,Menlo,monospace;}

  .pop{position:fixed;background:var(--surface-hi);border-left:3px solid var(--accent);border-radius:9px;
       width:min(600px,90vw);max-height:250px;overflow-y:auto;z-index:60;box-shadow:0 16px 44px rgba(0,0,0,.55);}
  .pop .ovrow{padding:5px 14px;font-size:12.5px;}
  .hidden{display:none !important;}

  .ctxmenu{display:none;}

  #toasts{position:fixed;top:14px;right:14px;z-index:90;display:flex;flex-direction:column;gap:8px;}
  .toast{background:var(--surface-hi);color:var(--text);border-left:3px solid var(--accent);border-radius:8px;
         padding:9px 14px;font-size:13px;box-shadow:0 10px 30px rgba(0,0,0,.5);max-width:340px;animation:tin .18s ease;}
  .toast.error{border-left-color:var(--red);}
  .toast.ok{border-left-color:var(--green);}
  @keyframes tin{from{opacity:0;transform:translateY(-6px);}to{opacity:1;transform:none;}}
  @media (max-width:1180px){aside.info{display:none;}}
  @media (max-width:860px){aside.side{display:none;}}
</style>
</head>
<body data-theme="default">
<header class="bar">
  <div class="brand"><span class="d">◆</span><b>enclave</b><span class="dimtxt"> · web</span>
    <button class="hbtn" id="tgSide" title="toggle sessions panel (Alt-S)">☰</button>
    <button class="hbtn" id="tgInfo" title="toggle info panel (Alt-I)">▤</button>
  </div>
  <div class="meta" id="meta">loading…</div>
</header>
<main>
  <aside class="side">
    <div class="sidehead">
      <div class="titlerow"><h2>sessions</h2><span class="add" id="graphBtn" title="branch graph">◎ graph</span><span class="add" id="newSess">+ new</span></div>
      <input id="sessSearch" class="minput" style="padding:6px 9px;font-size:12.5px" placeholder="search sessions…">
    </div>
    <div class="sesslist" id="sessions"></div>
  </aside>
  <section class="chat" id="chat"></section>
  <aside class="info" id="info"></aside>
</main>
<div class="composer" id="composer">
  <div class="prompt">❯</div>
  <textarea id="inp" rows="1" placeholder="ask anything…  ( /help · Ctrl-P palette · @file · !cmd )"></textarea>
  <span class="clip" id="clip" title="attach a file or image">📎</span>
  <button class="send" id="sendBtn" title="send (Enter)">send ⏎</button>
  <div id="attchips" class="attchips"></div>
</div>
<button id="jumpBtn" class="jumpbtn hidden" title="scroll to the latest message">↓ latest</button>
<div class="toolbar" id="toolbar">
  <span class="tb" data-cmd="/graph">◎ graph</span>
  <span class="tb" data-cmd="/sessions">sessions</span>
  <span class="tb" data-cmd="/new">+ new</span>
  <span class="tb" data-cmd="/model">model</span>
  <span class="tb" data-cmd="/effort">effort</span>
  <span class="tb" data-cmd="/provider">provider</span>
  <span class="tb" data-cmd="/theme">theme</span>
  <span class="tb" data-cmd="mode">plan/build</span>
  <span class="tb" data-cmd="/agent">agent</span>
  <span class="tb" data-cmd="/airgap">air-gap</span>
  <span class="tb" data-cmd="/route">route</span>
  <span class="tb" data-cmd="/ledger">ledger</span>
  <span class="tb" data-cmd="/memory">memory</span>
  <span class="tb" data-cmd="/decisions">decisions</span>
  <span class="tb" data-cmd="/exposure">exposure</span>
  <span class="tb" data-cmd="/context">context</span>
  <span class="tb" data-cmd="/rag">rag</span>
  <span class="tb" data-cmd="/find">find</span>
  <span class="tb" data-cmd="/search">search</span>
  <span class="tb" data-cmd="/undo">undo</span>
  <span class="tb" data-cmd="/retry">retry</span>
  <span class="tb" data-cmd="/export">export</span>
  <span class="tb" data-cmd="/help">/help</span>
</div>
<div class="privacy" id="privacy"></div>
<footer class="bar">
  <div style="min-width:0;overflow:hidden;white-space:nowrap;text-overflow:ellipsis">
    <span class="chip model" id="modelchip" title="click to pick a model">—</span><span class="chip agentchip" id="agentchip" title="toggle agentic tool mode">agent</span><span class="foot-status" id="status"></span>
  </div>
  <div class="foot-hint">palette<span class="k">Ctrl-P</span>sessions<span class="k">Ctrl-S</span>search<span class="k">Ctrl-R</span>find<span class="k">Ctrl-F</span></div>
</footer>
<div id="overlays"></div>
<div id="pop" class="pop hidden"></div>
<div id="toasts"></div>
<script>
const TOKEN = new URLSearchParams(location.search).get('token') || '';
const H = { 'x-enclave-token': TOKEN };
const HJSON = { 'x-enclave-token': TOKEN, 'content-type': 'application/json' };
const esc = s => String(s==null?'':s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const $ = id => document.getElementById(id);
let STATE=null, ACTIVE=null, ACTIVE_MESSAGES=null, STREAMING=false, STICK=true;
function scrollChat(){ const c=$('chat'); if(!c) return; ensureComposer(); if(STICK){ c.scrollTop=c.scrollHeight;
    requestAnimationFrame(()=>{ if(STICK){ c.scrollTop=c.scrollHeight; } }); }
  const near=c.scrollHeight-c.scrollTop-c.clientHeight<48; const jb=$('jumpBtn'); if(jb) jb.classList.toggle('hidden',near); }
// The composer lives inline at the end of the transcript (no fixed bottom bar).
function ensureComposer(){ const c=$('composer'), chat=$('chat'); if(c&&chat&&chat.lastElementChild!==c) chat.appendChild(c); }
function clearChat(){ const chat=$('chat'); if(!chat) return; Array.from(chat.children).forEach(ch=>{ if(ch.id!=='composer') ch.remove(); }); }

const PALETTE_COMMANDS = [
  ["/help","show all commands"],["/new","start a new session"],["/switch","open the session picker"],
  ["/branch","fork this conversation into a new branch"],["/log","show the conversation branch tree"],
  ["/graph","navigable branch graph"],["/checkout","switch to a branch"],["/diff","compare two sessions"],
  ["/model","pick a model"],["/effort","pick the reasoning effort"],["/connect","switch provider / add a key"],["/theme","pick a colour theme"],
  ["/plan","read-only plan mode"],["/build","build mode"],["/agent","toggle agentic tool mode"],["/clear","clear the view"],
  ["/undo","remove the last turn"],["/redo","restore the last undone turn"],["/retry","re-send the last message"],
  ["/compact","summarise and shrink the session"],["/find","search inside this conversation"],
  ["/search","search across all sessions"],["/export","export the chat (md/html/pdf)"],
  ["/ledger","show the encrypted egress ledger"],["/provenance","what left the machine for this session"],["/rag","local file index (index/search/status/clear)"],["/merge","merge a branch's new turns into this one"],["/blame","find which turn mentions some text"],["/init","generate an AGENTS.md for this project"],["/mcp","list tools exposed by MCP servers"],["/details","toggle tool detail blocks"],["/airgap","toggle air-gap"],
  ["/route","toggle routing of sensitive turns"],["/remember","save a fact to memory"],
  ["/memory","list / search memories"],["/forget","delete a memory"],["/checkpoint","summarise into memory"],
  ["/decide","record a decision with rationale"],["/decisions","list / search decisions"],["/exposure","privacy blast-radius + score"],["/context","explain what is sent this turn"],
  ["/panic","lock now"],["/quit","close the web UI"]
];
const THEMES=["default","nord","gruvbox","solarized","mono"];
const SLASH_REAL = new Set(['/help','/new','/switch','/theme','/themes','/model','/models','/effort','/connect','/provider','/providers','/plan','/build','/agent','/airgap','/route','/clear','/branch','/checkout','/graph','/tree','/log','/diff','/palette','/sessions','/resume','/continue','/quit','/find','/search','/search-all','/shortcuts','/keys','/ledger','/egress','/provenance','/rag','/merge','/init','/mcp','/blame','/details','/thinking','/memory','/memories','/remember','/forget','/checkpoint','/decide','/decisions','/exposure','/context','/export','/undo','/redo','/retry','/compact','/summarize']);

// ---------- small utils ----------
function fmtBytes(n){ n=+n||0; if(n>=1048576) return (n/1048576).toFixed(1)+' MB'; if(n>=1024) return (n/1024).toFixed(1)+' KB'; return n+' B'; }
function truncate(s,n){ s=String(s); return s.length<=n?s:s.slice(0,n-1)+'…'; }
function statusSet(text,kind){ const el=$('status'); el.textContent='  '+text; el.className='foot-status'+(kind?' '+kind:''); }
function toast(msg,kind){ const t=document.createElement('div'); t.className='toast'+(kind?' '+kind:''); t.textContent=msg; $('toasts').appendChild(t); setTimeout(()=>t.remove(),2800); }

// ---------- markdown (mirrors the TUI renderer) ----------
function inlineMD(txt){
  let out='', i=0;
  while(i<txt.length){
    const c=txt[i];
    if(c==='`'){ const j=txt.indexOf('`',i+1); if(j>i){ out+='<code>'+esc(txt.slice(i+1,j))+'</code>'; i=j+1; continue; } else { out+=esc(txt.slice(i)); break; } }
    if(c==='*'){ const two=txt[i+1]==='*'; const j=txt.indexOf(two?'**':'*', i+(two?2:1));
      if(j>i){ const inner=txt.slice(i+(two?2:1), j); out+= two?('<b>'+inlineMD(inner)+'</b>'):('<i>'+inlineMD(inner)+'</i>'); i=j+(two?2:1); continue; } }
    out+=esc(c); i++;
  }
  return out;
}
// ---------- code windows + split diff ----------
window.__cw=[];
function cwCopy(el,idx){ navigator.clipboard.writeText(window.__cw[idx]||'').then(()=>toast('copied','ok'),()=>toast('copy failed','error')); }
function cwRegister(text){ return window.__cw.push(text)-1; }
function isDiffText(code){
  const ls=String(code).split('\n');
  if(ls.some(l=>l.startsWith('@@'))) return true;
  let s=0; for(const l of ls){ if(l.startsWith('+')||l.startsWith('-')) s++; }
  return s>0 && s>=Math.max(1,Math.floor(ls.length*0.4));
}
function codeWindowHtml(code,lang){
  const ls=code.split('\n'); const id=cwRegister(code);
  let body='';
  ls.forEach((l,i)=>{ body+='<div class="crow"><span class="ln">'+(i+1)+'</span><span class="lc">'+esc(l||' ')+'</span></div>'; });
  return '<div class="codewin"><div class="cwhead"><span class="lang">'+esc(lang||'code')+'</span>'+
    '<span class="stats">'+ls.length+' lines</span>'+
    '<span class="cp" onclick="cwCopy(this,'+id+')">⧉ copy</span></div>'+
    '<div class="codegrid">'+body+'</div></div>';
}
// unified diff (1-char prefixes) or rendered diff (2-char prefixes) -> aligned rows
function diffRows(code,twoChar){
  const ls=String(code).replace(/\r/g,'').split('\n'); const rows=[]; let ln=1,rn=1,del=[],add=[];
  const flush=()=>{ const n=Math.max(del.length,add.length);
    for(let k=0;k<n;k++){ const d=del[k],a=add[k];
      rows.push({l: d!==undefined?{n:ln++,t:d,type:(a!==undefined?'mod':'del')}:null,
                 r: a!==undefined?{n:rn++,t:a,type:(d!==undefined?'mod':'add')}:null}); }
    del=[];add=[]; };
  ls.forEach((l,idx)=>{
    if(l.startsWith('@@')){ flush(); const m=l.match(/@@ -(\d+)(?:,\d+)? \+(\d+)/); if(m){ln=+m[1];rn=+m[2];} rows.push({sep:l}); return; }
    if(l.startsWith('+++')||l.startsWith('---')||l.startsWith('diff ')||l.startsWith('Index:')||l.startsWith('\\')){ flush(); return; }
    if(idx===0 && /\(\+\d+[^\d]/.test(l)) return; // "edited path (+N −M)" summary line
    if(l.startsWith('+ ')){ add.push(l.slice(2)); return; }
    if(l.startsWith('- ')){ del.push(l.slice(2)); return; }
    if(l.startsWith('  …')){ flush(); rows.push({sep:l.trim()}); return; }
    if(twoChar && l.startsWith('  ')){ flush(); const t=l.slice(2); rows.push({l:{n:ln++,t,type:'ctx'},r:{n:rn++,t,type:'ctx'}}); return; }
    if(l.startsWith('+')){ add.push(l.slice(1)); return; }
    if(l.startsWith('-')){ del.push(l.slice(1)); return; }
    flush();
    const t=(!twoChar && l.startsWith(' '))?l.slice(1):l;
    rows.push({l:{n:ln++,t,type:'ctx'},r:{n:rn++,t,type:'ctx'}});
  });
  flush();
  return rows;
}
function dcell(side){
  if(!side) return '<div class="drow empty"><span class="ln"></span><span class="lc"></span></div>';
  return '<div class="drow '+side.type+'"><span class="ln">'+side.n+'</span><span class="lc">'+esc(side.t||' ')+'</span></div>';
}
function splitDiffHtml(rows,lang,head){
  let L='',R='';
  for(const r of rows){
    if(r.sep!==undefined){ L+='<div class="drow sep"><span class="ln"></span><span class="lc">'+esc(r.sep)+'</span></div>';
      R+='<div class="drow sep"><span class="ln"></span><span class="lc">'+esc(r.sep)+'</span></div>'; continue; }
    L+=dcell(r.l); R+=dcell(r.r);
  }
  const id=cwRegister(rows.map(r=> r.sep!==undefined?r.sep:(' '+((r.l&&r.l.t)||''))).join('\n'));
  return '<div class="codewin">'+(head||'')+
    '<div class="splitdiff"><div class="pane"><div class="phead">before</div>'+L+'</div>'+
    '<div class="pane right"><div class="phead">after</div>'+R+'</div></div></div>';
}
function diffHeadHtml(label,added,removed,copyId){
  let s='<div class="cwhead"><span class="lang">'+esc(label)+'</span>';
  if(added!=null) s+='<span class="cadd">+'+added+'</span>';
  if(removed!=null) s+='<span class="cdel">−'+removed+'</span>';
  s+='<span class="cp" onclick="cwCopy(this,'+copyId+')">⧉ copy</span></div>';
  return s;
}

function renderMD(text){
  const lines=String(text).split('\n'); let html='', inCode=false, buf=[], lang='';
  const flushCode=()=>{ const code=buf.join('\n'); buf=[];
    if(isDiffText(code)) html+=splitDiffHtml(diffRows(code,false),lang);
    else html+=codeWindowHtml(code,lang);
  };
  for(const line of lines){
    if(line.trimStart().startsWith('```')){
      if(!inCode){ inCode=true; lang=line.trimStart().slice(3).trim(); buf=[]; }
      else { inCode=false; flushCode(); lang=''; }
      continue;
    }
    if(inCode){ buf.push(line); continue; }
    const t=line.trimStart();
    if(t.startsWith('#')){ const m=t.match(/^(#{1,3})\s+(.*)$/); if(m){ const lv=m[1].length; html+='<h'+lv+'>'+inlineMD(m[2])+'</h'+lv+'>'; continue; } }
    if(t.startsWith('>')){ html+='<blockquote>▌ '+inlineMD(t.slice(1).trim())+'</blockquote>'; continue; }
    if(/^[-*+]\s/.test(t)){ html+='<div>• '+inlineMD(t.replace(/^[-*+]\s/,''))+'</div>'; continue; }
    if(/^\d+\.\s/.test(t)){ html+='<div>&nbsp;&nbsp;'+inlineMD(t.replace(/^\d+\.\s/,''))+'</div>'; continue; }
    html += (line===''?'<div style="height:6px"></div>':('<p>'+inlineMD(line)+'</p>'));
  }
  if(inCode) flushCode();
  return '<div class="md">'+html+'</div>';
}

// ---------- render ----------
function renderHeader(){
  if(!STATE) return;
  const pill=(label,on,slash,title)=>'<span class="pill '+(on?'on':'off')+(label==='plan'?' plan':'')+'" data-slash="'+slash+'" title="'+title+'">'+label+'</span>';
  let m="session '"+esc(STATE.session.name)+"' · tools "+(STATE.tools?'on':'off')+" · guard "+esc(STATE.guard);
  m+=pill(STATE.mode, STATE.mode==='plan', STATE.mode==='plan'?'/build':'/plan','toggle plan / build mode');
  m+=pill('agent', STATE.agent, '/agent', 'toggle agentic tools');
  m+=pill('air-gap', STATE.air_gap, '/airgap', 'toggle air-gap (local only)');
  m+=pill('route', STATE.route_sensitive, '/route', 'route sensitive turns to local Ollama');
  $('meta').innerHTML=m;
}
function renderSessions(){
  const box=$('sessions'); if(!STATE) return;
  const q=($('sessSearch').value||'').toLowerCase();
  box.innerHTML='';
  const list=(STATE.sessions||[]).filter(s=> !q || s.name.toLowerCase().includes(q));
  if(!list.length){ box.innerHTML='<div class="ovempty">no sessions</div>'; return; }
  list.forEach(s=>{
    const cur=s.id===STATE.session.id;
    const el=document.createElement('div');
    el.className='sess'+(s.id===ACTIVE?' active':'');
    el.innerHTML='<span class="b">'+(cur?'●':'○')+'</span><span class="nm">'+esc(s.name)+'</span><span class="n">'+s.message_count+'</span>'+
      '<span class="acts"><span class="ren" title="rename">✎</span><span class="del" title="delete">🗑</span></span>';
    el.onclick=()=>openSession(s.id);
    el.querySelector('.ren').onclick=e=>{e.stopPropagation();renameSession(s);};
    el.querySelector('.del').onclick=e=>{e.stopPropagation();deleteSession(s);};
    el.addEventListener('contextmenu',e=>{e.preventDefault();openSessionMenu(s);});
    box.appendChild(el);
  });
}
function renderInfo(){
  const box=$('info'); if(!STATE) return;
  let ctxChars=0,nLines=0;
  (ACTIVE_MESSAGES||[]).forEach(m=>{ ctxChars+=(m.content||'').length; nLines+=(m.content||'').split('\n').length; });
  const estTok=Math.round(ctxChars/4);
  const krow=(k,v,cls)=>'<div class="row"><span class="k">'+k+'</span><span class="v'+(cls?' '+cls:'')+'">'+esc(v)+'</span></div>';
  let h='';
  h+=krow('session',STATE.session.name,'accent');
  h+=krow('id',STATE.session.id.slice(0,8));
  h+=krow('model',STATE.model,'accent');
  h+=krow('effort',STATE.effort);
  h+=krow('provider',STATE.provider);
  h+=krow('workdir',STATE.workspace);
  h+=krow('mode',STATE.mode,STATE.mode==='plan'?'warn':'');
  h+=krow('context','~'+estTok+' tok · '+nLines+' lines');
  h+=krow('tools',STATE.tools?'on':'off');
  h+=krow('agent',STATE.agent?'on':'off',STATE.agent?'ok':'');
  h+=krow('guard',STATE.guard);
  h+=krow('air-gap',STATE.air_gap?'on (local only)':'off',STATE.air_gap?'warn':'');
  h+=krow('routing',STATE.route_sensitive?'sensitive → local':'off',STATE.route_sensitive?'ok':'');
  h+='<div class="sec">storage</div>';
  h+=krow('db',fmtBytes(STATE.db_bytes)+' · SQLCipher');
  h+=krow('data',STATE.stats.messages+' msg · '+STATE.stats.sessions+' sessions');
  h+=krow('egress',STATE.egress_count+' sent');
  h+=krow('memory',STATE.memories_count+' facts');
  h+=krow('decisions',STATE.decisions_count+' logged');
  if(STATE.todos&&STATE.todos.length){
    h+='<div class="sec">tasks</div>';
    STATE.todos.slice(0,12).forEach(t=>{
      const s=(t.status||'').toLowerCase();
      const mark=(s==='done'||s==='completed'||s==='x')?'[x]':((s==='in_progress'||s==='doing'||s==='~')?'[~]':'[ ]');
      h+=krow(mark,truncate(t.text,40),mark==='[x]'?'ok':(mark==='[~]'?'warn':''));
    });
  }
  if(CHANGES.length){
    h+='<div class="sec">changes</div>';
    CHANGES.slice(-12).forEach(c=>{
      h+='<div class="row"><span class="k" style="color:var(--green)">+'+c.added+'</span><span class="k" style="color:var(--red)">−'+c.removed+'</span><span class="v">'+esc(c.path)+'</span></div>';
    });
  }
  box.innerHTML=h;
}
function renderPrivacy(){
  if(!STATE) return;
  $('privacy').textContent='▮ privacy · encrypted db '+fmtBytes(STATE.db_bytes)+' · '+STATE.stats.sessions+' sessions · '+
    STATE.stats.messages+' messages · egress '+STATE.egress_count+' · AES-256 (SQLCipher) · guard '+STATE.guard+' · telemetry off';
}
function renderFooter(){
  if(!STATE) return;
  $('modelchip').textContent=' '+STATE.provider+' · '+STATE.model+' ';
  const ac=$('agentchip'); ac.className='chip agentchip'+(STATE.agent?' on':''); ac.textContent='agent '+(STATE.agent?'on':'off');
  const cw=$('composer'); if(cw) cw.className='composer'+(STATE.mode==='plan'?' plan':'')+(STATE.agent?' agent':'');
}
function renderToolbar(){
  const tb=$('toolbar'); if(!tb||!STATE) return;
  const on={'/agent':STATE.agent,'/airgap':STATE.air_gap,'/route':STATE.route_sensitive,'mode':STATE.mode==='plan'};
  tb.querySelectorAll('.tb').forEach(el=>{ el.classList.toggle('on', !!on[el.dataset.cmd]); });
}
function applyState(s){ if(s){ STATE=s; renderAll(); } }
function renderAll(){ renderHeader(); renderSessions(); renderInfo(); renderPrivacy(); renderFooter(); renderToolbar(); }

function cardEl(m){
  const c=document.createElement('div'); c.className='card '+(m.role||'assistant');
  let inner='';
  if(m.role==='assistant'){ inner=renderMD(m.content); }
  else if(m.role==='tool'){ inner=m.content.split('\n').map(l=>{
      let col='var(--yellow)'; if(l.startsWith('+'))col='var(--green)'; else if(l.startsWith('-'))col='var(--red)'; else if(l.startsWith('@@')||l.startsWith('…'))col='var(--dim)';
      return '<div class="tool-line" style="color:'+col+'">'+esc(l)+'</div>'; }).join(''); }
  else { inner='<div style="white-space:pre-wrap;word-break:break-word">'+esc(m.content)+'</div>'; }
  if(m.tainted) inner+='<span class="badge">tainted</span>';
  if(m.attachments&&m.attachments.length){
    inner+='<div>';
    m.attachments.forEach(a=>{
      if(a.kind==='image'&&a.url) inner+='<div class="att"><img src="'+esc(a.url)+'"><span>'+esc(a.name)+'</span></div>';
      else inner+='<div class="att">📎 '+esc(a.name)+'</div>';
    });
    inner+='</div>';
  }
  if(m.tool_calls&&m.tool_calls.length) m.tool_calls.forEach(tc=>{ inner+='<div class="att">⚙ '+esc(tc.name)+'</div>'; });
  c.innerHTML=inner;
  if(m.role==='assistant'||m.role==='user'){
    const cp=document.createElement('span'); cp.className='copybtn'; cp.textContent='⧉'; cp.title='copy';
    cp.onclick=e=>{ e.stopPropagation(); navigator.clipboard.writeText(m.content||'').then(()=>toast('copied','ok'),()=>toast('copy failed','error')); };
    c.appendChild(cp);
  }
  return c;
}
function welcomeEl(){
  const tools=STATE&&STATE.tools;
  const rows=PALETTE_COMMANDS.slice(0,14).map(([k,d])=>'<div class="row"><span class="k">'+k+'</span><span class="d">'+esc(d)+'</span></div>').join('');
  const el=document.createElement('div'); el.className='card welcome';
  el.innerHTML='<h1>◆ ENCLAVE</h1><div class="sub">privacy-first AI · encrypted memory · zero telemetry</div>'+
    '<div class="sub">privacy guard: sensitive data is detected before sending — /airgap keeps everything local.</div>'+
    '<h3>commands</h3>'+rows+
    '<h3>keys</h3>'+
    '<div class="row"><span class="k">Ctrl-P</span><span class="d">command palette</span></div>'+
    '<div class="row"><span class="k">Ctrl-S</span><span class="d">session picker</span></div>'+
    '<div class="row"><span class="k">Enter</span><span class="d">send · Shift+Enter newline</span></div>'+
    (tools?'<div class="sub" style="margin-top:14px">the assistant may propose shell commands: each one asks first</div>'
          :'<div class="sub" style="margin-top:14px">tools disabled</div>');
  return el;
}
function renderChat(messages,opts){
  const chat=$('chat'); clearChat();
  STICK=true;
  if(messages===null||!messages.length){ chat.appendChild(welcomeEl()); ensureComposer(); return; }
  messages.forEach(m=>chat.appendChild(cardEl(m)));
  ensureComposer();
  if(opts&&opts.scroll!==false) scrollChat();
}

// ---------- agentic mode + usability helpers ----------
let CHANGES=[];
function addChange(c){ if(!c||!c.path) return; const i=CHANGES.findIndex(x=>x.path===c.path); if(i>=0) CHANGES[i]=c; else CHANGES.push(c); renderInfo(); }
function appendCard(m){ $('chat').appendChild(cardEl(m)); scrollChat(); }
function appendSystem(t){ appendCard({role:'system',content:t}); }
function colorizeTool(text){ return String(text||'').split('\n').map(l=>{
  let col='var(--yellow)';
  if(l.startsWith('+'))col='var(--green)'; else if(l.startsWith('-'))col='var(--red)'; else if(l.startsWith('@@')||l.startsWith('…'))col='var(--dim)';
  return '<div class="tool-line" style="color:'+col+'">'+esc(l)+'</div>'; }).join(''); }
function toolCard(out){
  const c=document.createElement('div'); c.className='card tool';
  if(out.change){
    const rows=diffRows(out.output||'',true);
    const id=cwRegister(rows.map(r=> r.sep!==undefined?r.sep:(' '+((r.l&&r.l.t)||''))).join('\n'));
    const L=rows.map(r=>r.sep!==undefined?'<div class="drow sep"><span class="ln"></span><span class="lc">'+esc(r.sep)+'</span></div>':dcell(r.l)).join('');
    const R=rows.map(r=>r.sep!==undefined?'<div class="drow sep"><span class="ln"></span><span class="lc">'+esc(r.sep)+'</span></div>':dcell(r.r)).join('');
    c.innerHTML='<div class="codewin">'+diffHeadHtml('⚙ '+out.name+' · '+out.change.path, out.change.added, out.change.removed, id)+
      '<div class="splitdiff"><div class="pane"><div class="phead">before</div>'+L+'</div>'+
      '<div class="pane right"><div class="phead">after</div>'+R+'</div></div></div>';
  } else {
    c.innerHTML='<div class="hdr">⚙ '+esc(out.name)+(out.denied?' · denied':'')+'</div>'+
      (out.denied?'<div class="tool-line tl-meta">'+esc(out.output||'')+'</div>':colorizeTool(out.output||''));
  }
  $('chat').appendChild(c); scrollChat();
}
function notify(msg){ try{ if(('Notification' in window)&&Notification.permission==='granted'){ new Notification('Enclave',{body:msg}); } }catch(e){} }
function askNotifyPermission(){ try{ if(('Notification' in window)&&Notification.permission==='default'){ Notification.requestPermission(); } }catch(e){} }

async function sendAgent(text,atts){
  const chat=$('chat'); if(chat.querySelector('.welcome')) clearChat();
  chat.appendChild(cardEl({role:'user',content:userText(text,atts)})); scrollChat();
  STREAMING=true; $('inp').disabled=true; statusSet('agent working…');
  window.__agentSteps=0;
  try{ const r=await api('/api/agent/start',{text,attachments:atts||[]}); applyAgent(r); }
  catch(e){ statusSet('error: '+e.message,'error'); toast(e.message,'error'); }
  STREAMING=false; $('inp').disabled=false; $('inp').focus();
}
function applyAgent(r){
  if(!r) return;
  if(r.state){ STATE=r.state; renderAll(); }
  const res=r.result; if(!res) return;
  if(res.text) appendCard({role:'assistant',content:res.text});
  if(res.type==='final'){ statusSet('ready'); notify('reply ready'); return; }
  if(res.type==='error'){ appendSystem('error: '+res.error); statusSet('error: '+res.error,'error'); return; }
  if(res.type==='tools'){
    (res.results||[]).forEach(out=>{ toolCard(out); if(out.change) addChange(out.change); });
    const ask=(res.calls||[]).filter(c=>c.suggested==='ask');
    if(ask.length) showApprove(res.calls,ask);
    else resumeAgent({});
  }
}
function showApprove(calls,ask){
  const chat=$('chat');
  const box=document.createElement('div'); box.className='approve';
  const head=document.createElement('div'); head.className='hdr';
  head.textContent='tool call'+(ask.length>1?'s':'')+' — nothing runs without your approval';
  box.appendChild(head);
  calls.forEach(c=>{ let args=c.arguments||''; try{ args=JSON.stringify(JSON.parse(args),null,2); }catch(e){}
    const d=document.createElement('div'); d.className='cmd'; d.textContent='⚙ '+c.name+'\n'+args; box.appendChild(d); });
  function resumeAll(){ const d={}; ask.forEach(c=>{ d[c.id]=c._d||'deny'; }); box.remove(); resumeAgent(d); }
  if(ask.length===1){
    const c=ask[0]; const row=document.createElement('div'); row.className='row';
    const by=document.createElement('button'); by.className='btn primary'; by.textContent='Run (y)';
    const bn=document.createElement('button'); bn.className='btn danger'; bn.textContent='Skip (n)';
    by.onclick=()=>{ c._d='approve'; resumeAll(); };
    bn.onclick=()=>{ c._d='deny'; resumeAll(); };
    row.append(by,bn); const h=document.createElement('span'); h.className='hint'; h.textContent='y run · n skip'; row.appendChild(h); box.appendChild(row);
  } else {
    ask.forEach(c=>{ const r=document.createElement('div'); r.className='row'; r.style.marginTop='6px';
      const lbl=document.createElement('span'); lbl.className='hint'; lbl.style.flex='1 1 auto'; lbl.textContent='⚙ '+c.name; r.appendChild(lbl);
      const by=document.createElement('button'); by.className='btn primary'; by.textContent='Run';
      const bn=document.createElement('button'); bn.className='btn danger'; bn.textContent='Skip';
      const done=()=>{ lbl.textContent='⚙ '+c.name+' — '+(c._d==='approve'?'run':'skip'); by.remove(); bn.remove(); if(ask.every(x=>x._d)) resumeAll(); };
      by.onclick=()=>{ c._d='approve'; done(); }; bn.onclick=()=>{ c._d='deny'; done(); };
      r.append(by,bn); box.appendChild(r); });
  }
  chat.appendChild(box); scrollChat(); notify('tool approval needed');
}
async function resumeAgent(decisions){
  if((window.__agentSteps=(window.__agentSteps||0)+1)>12){ statusSet('agent loop stopped (too many steps)','error'); return; }
  statusSet('agent working…');
  try{ const r=await api('/api/agent/resume',{decisions}); applyAgent(r); }
  catch(e){ statusSet('error: '+e.message,'error'); }
}
async function runShell(cmd){
  if(!cmd){ appendSystem('usage: !<shell command>'); return; }
  appendCard({role:'user',content:'!'+cmd}); statusSet('running…');
  try{ const r=await api('/api/shell',{cmd});
    if(r.error){ appendSystem('error: '+r.error); statusSet('error: '+r.error,'error'); return; }
    const c=document.createElement('div'); c.className='card tool'; c.innerHTML=colorizeTool(r.output||''); $('chat').appendChild(c); scrollChat();
    statusSet('command finished — output kept local');
  }catch(e){ statusSet('error: '+e.message,'error'); }
}
async function resolveAt(text){
  const parts=String(text).split(/(\s)/);
  for(let i=0;i<parts.length;i++){ const m=parts[i].match(/^@(.+)$/);
    if(m){ const p=m[1]; try{ const d=await (await fetch('/api/file?path='+encodeURIComponent(p),{headers:H})).json();
      if(d.content!=null) parts[i]='\n```'+p+'\n'+d.content+'\n```'; }catch(e){} } }
  return parts.join('');
}
function userText(text,atts){ return text; }
async function guardCheck(text){
  try{
    if(!STATE||STATE.guard==='off') return true;
    const r=await api('/api/scan',{text});
    const f=r.findings||[];
    if(!f.length) return true;
    const list=f.slice(0,8).map(x=>'  · '+x.kind+'  '+x.text).join('\n');
    const mode=STATE.guard;
    const msg=f.length+' sensitive item(s) detected before sending:\n'+list+
      (f.length>8?('\n  … and '+(f.length-8)+' more'):'')+
      '\n\nguard mode: '+mode+(mode==='on(auto)'?' — placeholders are applied automatically':'');
    return await askModal('privacy guard',msg,mode==='on(block)'?'Send anyway?':'Send anyway');
  }catch(e){ return true; }
}

// ---------- pickers / views ----------
const EFFORTS=[['default','use the model default'],['low','fastest, cheapest'],['medium','balanced'],['high','deepest reasoning']];
const PROVIDERS=['openrouter','openai','anthropic','ollama'];
function openEffort(){ openOverlay({title:'reasoning effort',filter:false,rows:EFFORTS.map(([k,d])=>({k,d,cur:k===STATE.effort})),
  hint:'↑/↓ move · Enter choose · Esc close',onPick:async r=>{ const rr=await api('/api/effort',{effort:r.k}); STATE=rr; renderAll(); toast('effort: '+r.k,'ok'); }}); }
function openProviders(){ openOverlay({title:'provider — switch model backend',filter:false,
  rows:PROVIDERS.map(p=>({k:p,d:p==='ollama'?'local (no key)':'needs an API key',cur:p===STATE.provider})),
  hint:'↑/↓ move · Enter switch · Esc close',onPick:async r=>{ const rr=await api('/api/provider',{provider:r.k}); if(rr.error){ toast(rr.error,'error'); return; } STATE=rr; renderAll(); toast('provider: '+r.k,'ok'); }}); }
async function openMemories(q){
  const d=await (await fetch('/api/memories'+(q?('?q='+encodeURIComponent(q)):''),{headers:H})).json();
  const mems=d.memories||[];
  openOverlay({title:'memory · '+mems.length+' fact(s)',filterPlaceholder:'filter…',
    rows:mems.map(m=>({k:truncate(m.text,30),d:(m.tags||'')+(m.pinned?' · pinned':'')+(m.local_only?' · local-only':''),id:m.id,
      actions:[{act:'del',label:'🗑'}],ondel:async()=>{ await api('/api/memories/delete',{id:m.id}); toast('deleted','ok'); closeOverlay(); openMemories(q); }})),
    hint:'Enter copies /forget id · 🗑 delete · Esc close',onPick:r=>{ $('inp').value='/forget '+r.id+' '; $('inp').focus(); }});
}
async function openDecisions(q){
  const d=await (await fetch('/api/decisions'+(q?('?q='+encodeURIComponent(q)):''),{headers:H})).json();
  const ds=d.decisions||[];
  openOverlay({title:'decisions · '+ds.length+' logged',filterPlaceholder:'filter…',
    rows:ds.map(x=>({k:'['+x.status+'] '+truncate(x.title,34),
      d:truncate(x.body||'',64)+(x.tags?(' · #'+x.tags):''),id:x.id,
      actions:[{act:'del',label:'🗑'}],
      ondel:async()=>{ await api('/api/decisions/delete',{id:x.id}); toast('decision forgotten','ok'); closeOverlay(); openDecisions(q); }})),
    hint:'Enter copies /decisions <title> · 🗑 forget · Esc close',onPick:r=>{ $('inp').value='/decisions '+r.k+' '; $('inp').focus(); }});
}
async function openExposure(){
  const d=await (await fetch('/api/exposure',{headers:H})).json();
  const b=d.blast_radius||{}, s=d.score||{};
  const rows=[];
  rows.push({k:'outbound',d:b.total+' request(s) · '+b.remote+' remote · '+b.local+' local · '+b.redacted+' redacted'});
  rows.push({k:'bytes sent',d:fmtBytes(b.bytes||0)});
  (b.providers||[]).forEach(p=>rows.push({k:p.name,d:p.count+' request(s)'}));
  if(!(b.kinds||[]).length){ rows.push({k:'sensitive',d:'none caught'}); }
  (b.kinds||[]).forEach(k=>rows.push({k:'caught',d:k.name+' ×'+k.count}));
  (s.factors||[]).forEach(f=>rows.push({k:(f.delta>=0?'+':'')+f.delta,d:f.label}));
  openOverlay({title:'privacy blast-radius · score '+s.score+'/100 (grade '+s.grade+')',rows,
    hint:'counts and kinds only — never payloads or secrets · Esc close',onPick:()=>{}});
}
async function openContext(){
  const r=await (await fetch('/api/context',{headers:H})).json();
  const rows=[];
  rows.push({k:'provider',d:r.provider+' · '+r.model+' · mode '+r.mode});
  (r.parts||[]).forEach(p=>rows.push({k:p.label,d:p.chars+' chars — '+p.detail}));
  if(!(r.parts||[]).length) rows.push({k:'system',d:'(none)'});
  rows.push({k:'history',d:r.messages+' message(s) · '+r.history_chars+' chars'});
  rows.push({k:'redactions',d:r.redactions||'none'});
  rows.push({k:'taint',d:r.taint?'on (flagged turns re-redacted)':'off'});
  let total='~'+r.est_tokens+' tokens · '+r.total_chars+' chars';
  if(r.limit_tokens){
    const pct=Math.round(r.est_tokens/r.limit_tokens*100);
    const filled=Math.round(Math.min(r.est_tokens,r.limit_tokens)/r.limit_tokens*10);
    const bar='['+('#'.repeat(filled))+('-'.repeat(10-filled))+']';
    total+=' · budget '+r.est_tokens+'/'+r.limit_tokens+' ('+pct+'%) '+bar;
    if(pct>=r.warn_pct) rows.push({k:'⚠ budget',d:'over '+r.warn_pct+'% — consider /compact or trimming memory/decisions'});
  }
  rows.push({k:'total sent',d:total});
  openOverlay({title:'context this turn',rows,
    hint:'this is exactly what composes the request — Esc close',onPick:()=>{}});
}
async function openLedger(perSession){
  const url='/api/ledger?verify=1'+(perSession?'&session=1':'');
  const d=await (await fetch(url,{headers:H})).json();
  const rows=(d.entries||[]).map(e=>({k:'#'+e.id+' '+e.provider+' · '+e.model,
    d:e.payload_bytes+'B · sha '+String(e.payload_sha).slice(0,12)+(e.redactions?(' · redacted: '+e.redactions):'')}));
  const title=(perSession?'provenance (this session)':'egress ledger')+' · '+d.count+' entries · chain '+(d.chain_ok?'OK':'BROKEN');
  openOverlay({title,rows,
    hint:'fingerprints only — never payloads or secrets · Esc close',onPick:()=>{}});
}
async function openDiff(a,b){
  if(!a||!b){ toast('usage: /diff <session a> <session b>','error'); return; }
  const d=await (await fetch('/api/diff?a='+encodeURIComponent(a)+'&b='+encodeURIComponent(b),{headers:H})).json();
  if(d.error){ toast(d.error,'error'); return; }
  const cls={add:'add',remove:'del',context:'ctx'};
  const html='<div class="diffsec">'+d.lines.map(l=>'<div class="'+cls[l.kind]+'">'+esc((l.kind==='add'?'+ ':l.kind==='remove'?'- ':'  ')+l.text)+'</div>').join('')+'</div>';
  const host=$('overlays'); const wrap=document.createElement('div'); wrap.className='overlay'; wrap.style.paddingTop='6vh';
  const box=document.createElement('div'); box.className='box graphbox';
  box.innerHTML='<div class="title">diff '+esc(a)+' → '+esc(b)+'   (+'+d.added+' −'+d.removed+')</div><div class="gscroll">'+html+'</div>';
  wrap.appendChild(box); host.appendChild(wrap); MODAL={close:closeModal};
  wrap.onclick=e=>{ if(e.target===wrap) closeModal(); };
}
async function openRag(arg){
  const parts=String(arg||'').trim().split(/\s+/); const sub=parts[0]||'';
  if(sub==='search'){
    const query=parts.slice(1).join(' ');
    const r=await api('/api/rag',{op:'search',q:query}); const hits=r.hits||[];
    openOverlay({title:'rag search · '+hits.length+' hit(s)',rows:hits.map(h=>({k:truncate(String(h.source).split('/').pop(),26),d:'score '+(+h.score).toFixed(2)+' · '+truncate(h.text,60)})),hint:'Esc close',onPick:()=>{}});
    return;
  }
  if(sub==='index'){
    const paths=parts.slice(1);
    if(!paths.length){ toast('usage: /rag index <paths…>','error'); return; }
    statusSet('indexing…');
    const r=await api('/api/rag',{op:'index',paths,replace:true});
    await loadState(); toast('indexed '+(r.files||0)+' file(s) · '+(r.chunks||0)+' chunk(s)','ok'); statusSet('ready'); return;
  }
  if(sub==='clear'){
    const ok=await askModal('RAG','Delete the entire local RAG index?','Delete','danger'); if(!ok) return;
    const r=await api('/api/rag',{op:'clear'}); toast('deleted '+(r.cleared||0)+' chunk(s)','ok'); return;
  }
  const r=await api('/api/rag',{op:'status'}); const srcs=r.sources||[];
  openOverlay({title:'rag index · '+(r.count||0)+' chunk(s) · '+srcs.length+' source(s)',
    rows:srcs.map(s=>({k:String(s.chunks),d:s.source})),
    hint:'/rag index <paths> · /rag search <q> · /rag clear · Esc close',onPick:()=>{}});
}
async function doMerge(arg){
  const key=String(arg||'').trim();
  if(!key){ toast('usage: /merge <branch name>','error'); return; }
  const r=await api('/api/merge',{source:key});
  if(r.error){ toast(r.error,'error'); return; }
  if(r.state){ applyState(r.state); await openCurrent(); }
  toast(r.merged>0?('merged '+r.merged+' message(s)'):'nothing new to merge','ok');
}
async function doInit(){
  if(!await askModal('Init','Generate an AGENTS.md for this project with the model?','Generate','')) return;
  statusSet('generating AGENTS.md…');
  const r=await api('/api/init',{});
  if(r.error){ toast(r.error,'error'); statusSet('ready'); return; }
  toast('wrote '+r.path,'ok'); statusSet('ready');
}
function openMcp(){
  const names=STATE.mcp_tools||[];
  openOverlay({title:'mcp tools · '+names.length,rows:names.map(n=>({k:'⚙',d:n})),hint:names.length?'Esc close':'no MCP servers configured (add [mcp.servers.<name>] to config.toml) · Esc',onPick:()=>{}});
}
function openBlame(arg){
  const q=String(arg||'').trim().toLowerCase();
  if(!q){ toast('usage: /blame <text>','error'); return; }
  const hits=[];
  (ACTIVE_MESSAGES||[]).forEach((m,i)=>{ const c=String(m.content||''); if(c.toLowerCase().includes(q)) hits.push({i,role:m.role,first:c.split('\n')[0]}); });
  openOverlay({title:'blame " '+arg+' " · '+hits.length+' match(es)',
    rows:hits.map(h=>({k:'#'+(h.i+1),d:h.role+' · '+truncate(h.first,60)})),
    hint:'matches in this branch · Esc close',onPick:()=>{}});
}
function toggleDetails(){
  document.body.classList.toggle('hidetools');
  const hidden=document.body.classList.contains('hidetools');
  toast('tool details '+(hidden?'hidden':'shown'),'ok');
}
async function doExport(fmt){
  const r=await fetch('/api/export',{method:'POST',headers:HJSON,body:JSON.stringify({format:fmt})});
  if(!r.ok){ toast('export failed','error'); return; }
  const blob=await r.blob(); const url=URL.createObjectURL(blob);
  const a=document.createElement('a'); a.href=url; a.download='enclave.'+fmt; a.click(); URL.revokeObjectURL(url);
  toast('exported '+fmt,'ok');
}

// ---------- data ----------
async function loadState(){
  const r=await fetch('/api/state',{headers:H});
  if(!r.ok){ $('meta').textContent='unauthorized'; statusSet('unauthorized','error'); return; }
  STATE=await r.json(); renderAll();
}
async function openSession(id){
  ACTIVE=id;
  const r=await fetch('/api/session/'+encodeURIComponent(id),{headers:H});
  const d=await r.json();
  ACTIVE_MESSAGES=d.messages||[];
  renderChat(ACTIVE_MESSAGES); renderSessions(); renderInfo();
  statusSet('viewing '+id.slice(0,8));
}
async function openCurrent(){ if(STATE){ await openSession(STATE.session.id); } }
async function api(path,body){ const r=await fetch(path,{method:'POST',headers:HJSON,body:JSON.stringify(body||{})}); return r.json(); }

// ---------- session actions ----------
async function newSession(){
  promptModal('New session','Name','',async name=>{
    if(name===null) return;
    await api('/api/session/new',{name:name||'chat'});
    await loadState(); await openCurrent(); toast('session created','ok');
  });
}
function renameSession(s){
  promptModal('Rename session','Name',s.name,async name=>{
    if(name===null||!name.trim()) return;
    const r=await api('/api/session/'+encodeURIComponent(s.id)+'/rename',{name:name.trim()});
    if(r.error){ toast(r.error,'error'); return; }
    await loadState();
    if(s.id===STATE.session.id) await openCurrent(); else renderSessions();
    toast('renamed','ok');
  });
}
function deleteSession(s){
  confirmModal('Delete session', "Delete \u201C"+s.name+"\u201D and all its messages? This cannot be undone.",
    async ()=>{ const r=await api('/api/session/'+encodeURIComponent(s.id)+'/delete',{});
      if(r.error){ toast(r.error,'error'); return; }
      const wasActive=(s.id===STATE.session.id);
      await loadState();
      if(wasActive) await openCurrent(); else { renderSessions(); if(ACTIVE===s.id) await openCurrent(); }
      toast('deleted','ok');
    }, 'Delete');
}
async function branchSession(s){
  const r=await api('/api/branch',{name:s.name+'~b'});
  if(r.error){ toast(r.error,'error'); return; }
  await loadState(); await openCurrent(); toast('branched','ok');
}
function openSessionMenu(s){
  const cur=STATE&&STATE.session?STATE.session.id:null;
  const isCur=s.id===cur;
  const rows=[
    {k:'Open',d:'show this conversation',act:'open'},
    {k:'Checkout',d:'make this the active session',act:'checkout'},
    {k:'Merge into current',d:isCur?'this is the current session':'append its new turns into the active session',act:'merge'},
    {k:'Diff vs current',d:'compare with the active session',act:'diff'},
    {k:'Branch from here',d:'fork a copy of this session',act:'branch'},
    {k:'Rename…',d:'change the session name',act:'ren'},
    {k:'Delete',d:'remove the session and all its messages',act:'del'},
  ];
  openOverlay({title:'session · '+s.name,filter:false,rows,hint:'Enter choose · r rename · d delete · Esc close',onPick:async r=>{
    if(r.act==='open') openSession(s.id);
    else if(r.act==='checkout'){ const rr=await api('/api/checkout',{id:s.id}); if(rr.error){toast(rr.error,'error');return;} STATE=rr; closeModal(); await loadState(); await openCurrent(); toast('checked out '+s.name,'ok'); }
    else if(r.act==='merge'){ if(isCur){toast('cannot merge a branch into itself','error');return;} const rr=await api('/api/merge',{source:s.id}); if(rr.error){toast(rr.error,'error');return;} if(rr.state) applyState(rr.state); closeModal(); await loadState(); await openCurrent(); toast(rr.merged>0?('merged '+rr.merged+' message(s)'):'nothing new to merge','ok'); }
    else if(r.act==='diff'){ if(isCur){toast('pick a different branch to diff','error');return;} closeModal(); openDiff(s.id,cur); }
    else if(r.act==='branch') branchSession(s);
    else if(r.act==='ren') renameSession(s);
    else if(r.act==='del') deleteSession(s);
  }});
  OV.onKey=e=>{ if(e.key==='r'){renameSession(s);return true;} if(e.key==='d'){deleteSession(s);return true;} return false; };
}

// ---------- modals ----------
let MODAL=null;
function closeModal(){ $('overlays').innerHTML=''; MODAL=null; }
function promptModal(title,label,value,onOk){
  closeModal(); const host=$('overlays');
  const wrap=document.createElement('div'); wrap.className='overlay';
  const box=document.createElement('div'); box.className='modal';
  box.innerHTML='<div class="title">'+esc(title)+'</div><label class="mlab">'+esc(label)+'</label>';
  const inp=document.createElement('input'); inp.className='minput'; inp.value=value||''; box.appendChild(inp);
  const btns=document.createElement('div'); btns.className='mbtns';
  const cancel=document.createElement('button'); cancel.className='btn'; cancel.textContent='Cancel';
  const ok=document.createElement('button'); ok.className='btn primary'; ok.textContent='OK';
  btns.append(cancel,ok); box.appendChild(btns); wrap.appendChild(box); host.appendChild(wrap);
  MODAL={close:closeModal}; inp.focus(); inp.select();
  cancel.onclick=()=>closeModal();
  ok.onclick=()=>{ const v=inp.value; closeModal(); onOk(v); };
  wrap.onclick=e=>{ if(e.target===wrap) closeModal(); };
  inp.onkeydown=e=>{ if(e.key==='Enter'){e.preventDefault();ok.click();} else if(e.key==='Escape'){e.preventDefault();closeModal();} };
}
function confirmModal(title,msg,onOk,okLabel){
  closeModal(); const host=$('overlays');
  const wrap=document.createElement('div'); wrap.className='overlay';
  const box=document.createElement('div'); box.className='modal';
  box.innerHTML='<div class="title">'+esc(title)+'</div><div style="color:var(--text);font-size:13.5px">'+esc(msg)+'</div>';
  const btns=document.createElement('div'); btns.className='mbtns';
  const cancel=document.createElement('button'); cancel.className='btn'; cancel.textContent='Cancel';
  const ok=document.createElement('button'); ok.className='btn danger'; ok.textContent=okLabel||'Delete';
  btns.append(cancel,ok); box.appendChild(btns); wrap.appendChild(box); host.appendChild(wrap);
  MODAL={close:closeModal};
  cancel.onclick=()=>closeModal(); ok.onclick=()=>{closeModal();onOk();}; wrap.onclick=e=>{if(e.target===wrap)closeModal();};
}
function askModal(title,msg,okLabel,okClass){
  return new Promise(res=>{
    closeModal(); const host=$('overlays');
    const wrap=document.createElement('div'); wrap.className='overlay';
    const box=document.createElement('div'); box.className='modal';
    box.innerHTML='<div class="title">'+esc(title)+'</div><div style="color:var(--text);font-size:13.5px;white-space:pre-wrap">'+esc(msg)+'</div>';
    const btns=document.createElement('div'); btns.className='mbtns';
    const cancel=document.createElement('button'); cancel.className='btn'; cancel.textContent='Cancel';
    const ok=document.createElement('button'); ok.className='btn '+(okClass||'primary'); ok.textContent=okLabel||'OK';
    btns.append(cancel,ok); box.appendChild(btns); wrap.appendChild(box); host.appendChild(wrap);
    const done=v=>{ closeModal(); res(v); };
    MODAL={close:()=>done(false)};
    cancel.onclick=()=>done(false); ok.onclick=()=>done(true); wrap.onclick=e=>{ if(e.target===wrap) done(false); };
    ok.focus();
  });
}

// ---------- overlays (palette / pickers / sessions) ----------
let OV=null;
function closeOverlay(){ $('overlays').innerHTML=''; OV=null; }
function openOverlay(cfg){
  closeModal(); const host=$('overlays');
  const wrap=document.createElement('div'); wrap.className='overlay';
  const box=document.createElement('div'); box.className='box';
  box.innerHTML='<div class="title">'+esc(cfg.title)+'</div>';
  let filterEl=null;
  if(cfg.filter!==false){ filterEl=document.createElement('input'); filterEl.className='ovfilter'; filterEl.style.margin='0 16px 8px'; filterEl.style.width='calc(100% - 32px)'; filterEl.placeholder=cfg.filterPlaceholder||'filter…'; box.appendChild(filterEl); }
  const list=document.createElement('div'); list.className='ovlist'; box.appendChild(list);
  const hint=document.createElement('div'); hint.className='ovhint'; hint.textContent=cfg.hint||'↑/↓ move · Enter choose · Esc close';
  box.appendChild(hint); wrap.appendChild(box); host.appendChild(wrap);
  wrap.onclick=e=>{ if(e.target===wrap) closeOverlay(); };
  OV={all:cfg.rows||[],rows:[],sel:0,list,filterEl,onPick:cfg.onPick,onKey:cfg.onKey,box};
  if(filterEl){ filterEl.oninput=()=>{OV.sel=0;drawOv();}; filterEl.focus(); }
  drawOv();
}
function drawOv(){
  if(!OV) return;
  const q=(OV.filterEl?OV.filterEl.value:'').toLowerCase();
  OV.rows=OV.all.filter(r=>!q||(r.k+' '+(r.d||'')).toLowerCase().includes(q));
  if(OV.sel>=OV.rows.length) OV.sel=Math.max(0,OV.rows.length-1);
  if(OV.sel<0) OV.sel=0;
  OV.list.innerHTML='';
  if(!OV.rows.length){ OV.list.innerHTML='<div class="ovempty">no matches</div>'; return; }
  OV.rows.forEach((r,i)=>{
    const el=document.createElement('div');
    el.className='ovrow'+(i===OV.sel?' sel':'')+(r.cur?' cur':'');
    let inner='<span class="c">'+esc(r.k)+'</span>'+(r.d?('<span class="d">'+esc(r.d)+'</span>'):'<span class="d"></span>');
    if(r.actions) inner+='<span class="ra">'+r.actions.map(a=>'<span data-act="'+a.act+'">'+a.label+'</span>').join('')+'</span>';
    el.innerHTML=inner;
    el.onmouseenter=()=>{ OV.sel=i; syncOv(); };
    el.onclick=(e)=>{ const act=e.target.dataset&&e.target.dataset.act;
      if(act&&r['on'+act]){ e.stopPropagation(); r['on'+act](); return; } pickOv(); };
    OV.list.appendChild(el);
  });
  syncOv();
}
function syncOv(){
  if(!OV) return;
  [...OV.list.children].forEach((el,i)=>el.classList.toggle('sel',i===OV.sel));
  const el=OV.list.children[OV.sel];
  if(el&&el.scrollIntoView) el.scrollIntoView({block:'nearest'});
}
function ovMove(d){ if(!OV||!OV.rows.length) return; OV.sel=(OV.sel+d+OV.rows.length)%OV.rows.length; syncOv(); }
function pickOv(){ if(!OV) return; const r=OV.rows[OV.sel]; const cb=OV.onPick; closeOverlay(); if(r&&cb) cb(r); }

function openPalette(){ openOverlay({title:'command palette',filterPlaceholder:'type to filter commands…',rows:PALETTE_COMMANDS.map(([k,d])=>({k,d})),onPick:r=>{ $('inp').value=r.k+' '; autosize($('inp')); $('inp').focus(); }}); }
function openShortcuts(){ openOverlay({title:'shortcuts',filter:false,rows:PALETTE_COMMANDS.map(([k,d])=>({k,d})),hint:'press Esc to close',onPick:()=>{}}); }
function openThemes(){ openOverlay({title:'theme',filter:false,rows:THEMES.map(t=>({k:t,d:'',cur:t===document.body.dataset.theme})),onPick:r=>setTheme(r.k)}); }
async function openModels(){
  statusSet('loading models…'); toast('loading model list…');
  const r=await fetch('/api/models',{headers:H}); const d=await r.json();
  openOverlay({title:'models — '+d.provider,rows:(d.models||[]).map(m=>({k:m.id,d:m.meta,cur:m.id===STATE.model})),
    onPick:async r=>{ await api('/api/model',{model:r.k}); await loadState(); toast('model '+r.k+' (saved)','ok'); }});
  statusSet('ready');
}
function openSessions(){
  const rows=(STATE.sessions||[]).map(s=>({k:s.name,d:s.message_count+' msg · '+s.id.slice(0,8),cur:s.id===STATE.session.id,id:s.id,sess:s,
    actions:[{act:'ren',label:'✎'},{act:'del',label:'🗑'}],
    onren:()=>renameSession(s), ondel:()=>deleteSession(s)}));
  openOverlay({title:'sessions',filterPlaceholder:'filter sessions…  (r rename · d delete · Esc close)',rows,
    hint:'Enter open · r rename · d delete · n new · Esc close',
    onPick:r=>openSession(r.id)});
  OV.onKey=e=>{
    const r=OV.rows[OV.sel]; if(!r) return false;
    if(e.key==='r'){ renameSession(r.sess); return true; }
    if(e.key==='d'){ deleteSession(r.sess); return true; }
    if(e.key==='n'){ newSession(); return true; }
    return false;
  };
}
async function openSearch(){
  openOverlay({title:'search across all sessions',rows:[],filterPlaceholder:'type to search the encrypted database…',
    hint:'↑/↓ move · Enter opens the session · Esc close',onPick:r=>openSession(r.id)});
  const f=OV.filterEl; if(!f) return;
  const run=async()=>{ const q=f.value.trim(); if(!q){ OV.all=[]; OV.sel=0; drawOv(); return; }
    statusSet('searching…');
    try{ const r=await fetch('/api/search?q='+encodeURIComponent(q),{headers:H}); const d=await r.json();
      OV.all=(d.hits||[]).map(h=>({k:h.session_name,d:'['+h.role+'] '+h.snippet,id:h.session_id}));
    }catch(e){ OV.all=[]; }
    OV.sel=0; drawOv(); statusSet((OV.all.length)+' hit(s)'); };
  let t=null; f.oninput=()=>{ clearTimeout(t); t=setTimeout(run,180); };
}
function openFind(){
  const build=q=>{ q=q.toLowerCase(); const out=[];
    (ACTIVE_MESSAGES||[]).forEach((m,ci)=>{ (m.content||'').split('\n').forEach(ln=>{
      if(!q||ln.toLowerCase().includes(q)) out.push({k:(m.role==='user'?'you':m.role),d:truncate(ln||'·',72),ci}); }); });
    return q?out:out.slice(0,60); };
  openOverlay({title:'find in conversation',rows:build(''),filterPlaceholder:'type to search this conversation…',
    hint:'↑/↓ move · Enter jumps to the message · Esc close',onPick:r=>scrollToCard(r.ci)});
  OV.filterEl.oninput=()=>{ OV.all=build(OV.filterEl.value); OV.sel=0; drawOv(); };
}
function scrollToCard(i){ const el=$('chat').children[i]; if(el) el.scrollIntoView({block:'center'}); }

// ---------- branch graph ----------
function graphSVG(d,sel){
  const nodes=d.nodes||[], cur=d.current;
  if(!nodes.length) return '<div class="ovempty">no branches yet — use /branch to fork this conversation</div>';
  const byId={}; nodes.forEach(n=>byId[n.id]=n);
  const children={};
  nodes.forEach(n=>{ const p=(n.parent&&byId[n.parent])?n.parent:'__root__'; (children[p]=children[p]||[]).push(n.id); });
  Object.values(children).forEach(a=>a.sort((x,y)=>byId[x].name.localeCompare(byId[y].name)));
  const roots=(children['__root__']||[]).slice();
  const NW=200, NH=52, HGAP=30, VGAP=80;
  let cursor=0; const pos={}, depth={};
  function walk(id,dep){
    depth[id]=dep; const ch=children[id]||[];
    if(!ch.length){ const x=cursor; cursor+=NW+HGAP; pos[id]={x,y:dep*(NH+VGAP)}; return x+NW/2; }
    const xs=ch.map(c=>walk(c,dep+1));
    const cx=(Math.min.apply(null,xs)+Math.max.apply(null,xs))/2;
    pos[id]={x:cx-NW/2, y:dep*(NH+VGAP)}; return cx;
  }
  roots.forEach(r=>{ walk(r,0); cursor+=HGAP; });
  const maxDep=Math.max.apply(null, Object.values(depth).concat([0]));
  const W=Math.max(cursor+8,NW), H=(maxDep+1)*(NH+VGAP);
  let edges='', boxes='';
  nodes.forEach(n=>{
    if(!n.parent||!byId[n.parent]) return;
    const p=pos[n.parent], c=pos[n.id]; if(!p||!c) return;
    const x1=p.x+NW/2, y1=p.y+NH, x2=c.x+NW/2, y2=c.y;
    const onPath=(n.id===cur)||(n.parent===cur);
    edges+='<path class="gedge'+(onPath?' cur':'')+'" d="M'+x1+' '+y1+' C'+x1+' '+(y1+44)+' '+x2+' '+(y2-44)+' '+x2+' '+y2+'"/>';
    if(n.from>=0) edges+='<text class="glabel" x="'+((x1+x2)/2+6)+'" y="'+((y1+y2)/2)+'">@'+n.from+'</text>';
  });
  nodes.forEach(n=>{
    const p=pos[n.id]; if(!p) return;
    const isCur=n.id===cur;
    const sub=n.message_count+' msg · '+(n.parent?'fork @'+(n.from<0?'?':n.from):'root')+(isCur?' · current':'');
    boxes+='<g class="gnode'+(isCur?' cur':'')+(n.id===sel?' sel':'')+'" data-id="'+esc(n.id)+'" transform="translate('+p.x+','+p.y+')">'+
      '<rect x="0" y="0" width="'+NW+'" height="'+NH+'" rx="9"/>'+
      '<text x="13" y="22">'+esc(truncate(n.name,23))+'</text>'+
      '<text class="sub" x="13" y="39">'+esc(sub)+'</text>'+
      '</g>';
  });
  return '<svg class="graphsvg" width="'+W+'" height="'+H+'" viewBox="0 0 '+W+' '+H+'">'+edges+boxes+'</svg>';
}
async function openGraph(){
  closeModal(); closeOverlay();
  const host=$('overlays');
  const wrap=document.createElement('div'); wrap.className='overlay'; wrap.style.paddingTop='5vh';
  const box=document.createElement('div'); box.className='box graphbox';
  box.innerHTML='<div class="title">branch graph</div><div class="gactions"></div><div class="gscroll"><div style="color:var(--dim);font-size:13px">loading…</div></div>';
  wrap.appendChild(box); host.appendChild(wrap);
  MODAL={close:closeModal};
  wrap.onclick=e=>{ if(e.target===wrap) closeModal(); };
  let d;
  try{ d=await (await fetch('/api/graph',{headers:H})).json(); }
  catch(e){ box.querySelector('.gscroll').innerHTML='<div style="color:var(--red)">failed to load the branch graph</div>'; return; }
  const nodes=d.nodes||[], cur=d.current;
  let sel=cur, selName=(nodes.find(n=>n.id===cur)||{}).name||cur;
  const scroll=box.querySelector('.gscroll'), actions=box.querySelector('.gactions');
  const nameOf=id=>{ const n=nodes.find(x=>x.id===id); return n?n.name:id; };
  const render=()=>{
    scroll.innerHTML='<div class="legend"><b>●</b> current · <b>○</b> other · <b>@N</b> forked from message N · click to select · double-click to open · Esc closes</div>'+graphSVG(d,sel);
    scroll.querySelectorAll('.gnode').forEach(g=>{
      g.onclick=()=>{ sel=g.dataset.id; selName=nameOf(sel); refresh(); };
      g.ondblclick=()=>{ closeModal(); openSession(g.dataset.id); };
    });
  };
  const act=(label,cls,fn)=>{ const b=document.createElement('span'); b.className='gbtn'+(cls?' '+cls:''); b.textContent=label; b.onclick=fn; return b; };
  const renderActions=()=>{
    actions.innerHTML='';
    actions.appendChild(act('open','',()=>{ closeModal(); openSession(sel); }));
    actions.appendChild(act('checkout','',async()=>{ const r=await api('/api/checkout',{id:sel}); if(r.error){toast(r.error,'error');return;} STATE=r; closeModal(); await loadState(); await openCurrent(); toast('checked out '+selName,'ok'); }));
    actions.appendChild(act('merge → current','',async()=>{ if(sel===cur){toast('cannot merge a branch into itself','error');return;} const r=await api('/api/merge',{source:sel}); if(r.error){toast(r.error,'error');return;} if(r.state) applyState(r.state); closeModal(); await loadState(); await openCurrent(); toast(r.merged>0?('merged '+r.merged+' message(s)'):'nothing new to merge','ok'); }));
    actions.appendChild(act('diff vs current','',()=>{ if(sel===cur){toast('select a different branch to diff','error');return;} closeModal(); openDiff(sel,cur); }));
    actions.appendChild(act('branch from here','',async()=>{ const r=await api('/api/branch',{parent:sel,name:selName+'~b'}); if(r.error){toast(r.error,'error');return;} applyState(r); closeModal(); await loadState(); await openCurrent(); toast('branched from '+selName,'ok'); }));
    actions.appendChild(act('rename','',()=>{ closeModal(); promptModal('Rename session','New name',selName,async v=>{ if(!v||!v.trim())return; const r=await api('/api/session/'+encodeURIComponent(sel)+'/rename',{name:v.trim()}); if(r.error){toast(r.error,'error');return;} await loadState(); await openCurrent(); toast('renamed','ok'); }); }));
    actions.appendChild(act('delete','danger',()=>{ closeModal(); confirmModal('Delete session','Delete "'+selName+'"? This cannot be undone.',async()=>{ const r=await api('/api/session/'+encodeURIComponent(sel)+'/delete',{}); if(r.error){toast(r.error,'error');return;} if(r.state) applyState(r.state); await loadState(); await openCurrent(); toast('deleted','ok'); },'Delete'); }));
    const s=document.createElement('span'); s.className='gsel'; s.textContent='selected: '+selName; actions.appendChild(s);
  };
  const refresh=()=>{ render(); renderActions(); };
  box.querySelector('.title').textContent='branch graph · '+nodes.length+' branch(es)';
  refresh();
  statusSet('branch graph — click to select, double-click to open, use the buttons');
}

// ---------- input popups (slash + @file) ----------
let POP_ROWS=[], POP_KIND=null, POP_SEL=0;
function hidePop(){ $('pop').classList.add('hidden'); POP_ROWS=[]; POP_KIND=null; }
function showPop(rows,kind){
  POP_ROWS=rows; POP_KIND=kind; POP_SEL=0;
  const pop=$('pop');
  if(!rows.length){ hidePop(); return; }
  pop.classList.remove('hidden');
  const rect=$('inp').getBoundingClientRect();
  pop.style.left=Math.max(8,rect.left-14)+'px';
  pop.style.width=Math.min(600,rect.width+40)+'px';
  pop.style.top='auto'; pop.style.bottom=(window.innerHeight-rect.top+6)+'px';
  drawPop();
}
function drawPop(){
  const pop=$('pop');
  pop.innerHTML=POP_ROWS.map((r,i)=>'<div class="ovrow'+(i===POP_SEL?' sel':'')+'" data-i="'+i+'"><span class="c">'+esc(r.k)+'</span><span class="d">'+esc(r.d||'')+'</span></div>').join('');
  const el=pop.children[POP_SEL]; if(el&&el.scrollIntoView) el.scrollIntoView({block:'nearest'});
}
function popMove(d){ if(!POP_ROWS.length) return; POP_SEL=(POP_SEL+d+POP_ROWS.length)%POP_ROWS.length; drawPop(); }
function applyPop(){
  const r=POP_ROWS[POP_SEL]; if(!r) return;
  if(POP_KIND==='slash'){ $('inp').value=r.k+' '; }
  else { $('inp').value=replaceAt($('inp').value,r.k); }
  hidePop(); autosize($('inp')); $('inp').focus();
}
function replaceAt(v,path){ const m=v.match(/(^|\s)@([^\s]*)$/); if(!m) return v+' @'+path+' '; return v.slice(0,v.length-m[2].length)+path+' '; }
let FILES=null;
async function ensureFiles(){ if(FILES) return FILES; try{ const r=await fetch('/api/files',{headers:H}); FILES=(await r.json()).files||[]; }catch(e){ FILES=[]; } return FILES; }
async function updatePop(){
  const v=$('inp').value;
  if(/^\/[^\s]*$/.test(v)){
    const q=v.slice(1).toLowerCase();
    const rows=PALETTE_COMMANDS.filter(([k])=>k.slice(1).toLowerCase().includes(q)).map(([k,d])=>({k,d}));
    showPop(rows,'slash'); return;
  }
  const m=v.match(/(^|\s)@([^\s]*)$/);
  if(m){
    const q=m[2].toLowerCase();
    const files=await ensureFiles();
    const rows=files.filter(f=>f.toLowerCase().includes(q)).slice(0,40).map(f=>({k:f,d:'file'}));
    showPop(rows,'file'); return;
  }
  hidePop();
}

// ---------- streaming send ----------
let ABORT=null;
async function sendText(text,atts){
  if(!text||STREAMING) return;
  const inp=$('inp');
  const chat=$('chat');
  if(chat.querySelector('.welcome')) clearChat();
  STICK=true;
  chat.appendChild(cardEl({role:'user',content:text,attachments:(atts||[]).map(a=>({kind:a.kind,name:a.name}))}));
  scrollChat();
  const live=cardEl({role:'assistant',content:''}); live.id='livecard';
  live.innerHTML='<span style="color:var(--dim)">…</span>';
  chat.appendChild(live); scrollChat();
  STREAMING=true; inp.disabled=true; statusSet('streaming…');
  let acc='';
  try{
    ABORT=new AbortController();
    const r=await fetch('/api/send',{method:'POST',headers:HJSON,body:JSON.stringify({text,attachments:atts||[]}),signal:ABORT.signal});
    if(!r.ok||!r.body){ const e=await r.json().catch(()=>({error:'send failed'})); throw new Error(e.error||r.statusText); }
    const reader=r.body.getReader(); const dec=new TextDecoder(); let buf='';
    for(;;){
      const {value,done}=await reader.read(); if(done) break;
      buf+=dec.decode(value,{stream:true});
      let idx;
      while((idx=buf.indexOf('\n\n'))>=0){
        const block=buf.slice(0,idx); buf=buf.slice(idx+2);
        let ev='message',data='';
        block.split('\n').forEach(l=>{ if(l.startsWith('event:'))ev=l.slice(6).trim(); else if(l.startsWith('data:'))data+=l.slice(5).trim(); });
        if(ev==='delta'){ try{ acc+=JSON.parse(data); }catch(e){} live.innerHTML=renderMD(acc); scrollChat(); }
        else if(ev==='error'){ try{ statusSet('error: '+JSON.parse(data),'error'); toast('error: '+JSON.parse(data),'error'); }catch(e){ statusSet('error','error'); } }
        else if(ev==='done'){ try{ acc=JSON.parse(data); }catch(e){} }
      }
    }
  }catch(e){ statusSet('error: '+e.message,'error'); toast(e.message,'error'); }
  STREAMING=false; inp.disabled=false; ABORT=null;
  live.removeAttribute('id'); live.innerHTML=renderMD(acc)||'<span style="color:var(--dim)">…</span>';
  await loadState(); await openCurrent(); statusSet('ready'); notify('reply ready'); inp.focus();
}

// ---------- slash commands ----------
let LAST_UNDONE=null;
async function runSlash(text){
  const parts=text.trim().split(/\s+/); const cmd=parts[0].slice(1); const arg=parts.slice(1).join(' ');
  if(!SLASH_REAL.has('/'+cmd)){ toast('/'+cmd+' is TUI-only — use it in the terminal','error'); statusSet('web UI: /'+cmd+' is TUI-only'); return; }
  switch(cmd){
    case 'help': openShortcuts(); break;
    case 'new': newSession(); break;
    case 'switch': case 'sessions': case 'resume': case 'continue': openSessions(); break;
    case 'theme': case 'themes': if(arg) setTheme(arg); else openThemes(); break;
    case 'model': case 'models': if(arg){ await api('/api/model',{model:arg}); await loadState(); toast('model '+arg+' (saved)','ok'); } else openModels(); break;
    case 'effort': if(arg){ const r=await api('/api/effort',{effort:arg}); STATE=r; renderAll(); toast('effort: '+arg,'ok'); } else openEffort(); break;
    case 'connect': case 'provider': case 'providers': openProviders(); break;
    case 'plan': await api('/api/toggle',{plan:true}); await loadState(); toast('plan mode — read-only'); break;
    case 'build': await api('/api/toggle',{plan:false}); await loadState(); toast('build mode'); break;
    case 'agent': { const on=!STATE.agent; await api('/api/toggle',{agent:on}); await loadState(); toast('agent mode '+(on?'ON':'OFF')); break; }
    case 'airgap': { const on=!STATE.air_gap; await api('/api/toggle',{air_gap:on}); await loadState(); toast('air-gap '+(on?'ON':'OFF')); break; }
    case 'route': { const on=!STATE.route_sensitive; await api('/api/toggle',{route_sensitive:on}); await loadState(); toast('sensitive routing '+(on?'ON':'OFF')); break; }
    case 'clear': { const chat=$('chat'); clearChat(); chat.appendChild(welcomeEl()); ensureComposer(); ACTIVE_MESSAGES=[]; renderInfo(); toast('view cleared'); break; }
    case 'branch': {
      const toks=String(arg||'').trim().split(/\s+/).filter(Boolean);
      let from=null; const names=[];
      for(let i=0;i<toks.length;i++){ if(toks[i]==='--from'&&toks[i+1]){ from=parseInt(toks[i+1],10); i++; } else names.push(toks[i]); }
      const bname=names.join(' ');
      const r=await api('/api/branch',{name:bname,from:(from!=null&&!isNaN(from))?from:undefined});
      if(r.error){ toast(r.error,'error'); break; }
      applyState(r); await loadState(); await openCurrent();
      toast('branched'+(bname?(' to '+bname):'')+((from!=null)?(' from message '+from):''),'ok'); break;
    }
    case 'checkout': { const r=await api('/api/checkout',{id:arg}); if(r.error){ toast(r.error,'error'); break; } STATE=r; await openCurrent(); toast('checked out '+arg,'ok'); break; }
    case 'graph': case 'tree': openGraph(); break;
    case 'log': case 'tree-log': openGraph(); break;
    case 'diff': openDiff(parts[1],parts[2]); break;
    case 'ledger': case 'egress': openLedger(false); break;
    case 'provenance': openLedger(true); break;
    case 'rag': openRag(arg); break;
    case 'merge': await doMerge(arg); break;
    case 'init': await doInit(); break;
    case 'mcp': openMcp(); break;
    case 'blame': openBlame(arg); break;
    case 'details': case 'thinking': toggleDetails(); break;
    case 'memory': case 'memories': openMemories(arg||''); break;
    case 'decide': promptModal('Record decision','Title :: rationale',arg||'',async v=>{ if(!v||!v.trim()) return; const [t,b]=v.split('::'); const r=await api('/api/decisions',{title:(t||v).trim(),body:(b||'').trim()}); if(r.error){ toast(r.error,'error'); return; } await loadState(); toast('decision recorded','ok'); }); break;
    case 'decisions': openDecisions(arg||''); break;
    case 'exposure': case 'blast-radius': openExposure(); break;
    case 'context': openContext(); break;
    case 'remember': promptModal('Remember','Fact to store',arg||'',async v=>{ if(!v||!v.trim()) return; const r=await api('/api/memories',{text:v.trim()}); if(r.error){ toast(r.error,'error'); return; } await loadState(); toast('remembered','ok'); }); break;
    case 'forget': if(!arg){ toast('usage: /forget <id>','error'); break; } { const r=await api('/api/memories/delete',{id:arg}); await loadState(); toast(r.ok?'forgotten':'not found', r.ok?'ok':'error'); } break;
    case 'checkpoint': { const prompt='Summarise the key facts, decisions, preferences and open questions in this conversation into a short bullet list suitable for long-term memory.'; statusSet('summarising…'); const text=await resolveAt(parts.slice(1).join(' ')||''); const r=await api('/api/memories',{text:prompt,tags:'checkpoint'}); await loadState(); toast('checkpoint hint stored','ok'); break; }
    case 'export': doExport((arg||'html').trim()); break;
    case 'undo': { const r=await api('/api/history',{op:'undo'}); if(r.error){ toast(r.error,'error'); break; } LAST_UNDONE=r.result.text; $('inp').value=LAST_UNDONE||''; autosize($('inp')); $('inp').focus(); await loadState(); await openCurrent(); toast('undone — edit and press Enter, or /redo'); break; }
    case 'redo': if(LAST_UNDONE){ $('inp').value=LAST_UNDONE; autosize($('inp')); $('inp').focus(); toast('restored — press Enter to send'); } else toast('nothing to redo'); break;
    case 'retry': { const r=await api('/api/history',{op:'retry'}); if(r.error){ toast(r.error,'error'); break; } await loadState(); await openCurrent(); const t=r.result.text; if(t){ if(STATE.agent) await sendAgent(t,[]); else await sendText(t,[]); } break; }
    case 'compact': case 'summarize': { statusSet('compacting…'); const r=await api('/api/history',{op:'compact'}); if(r.error){ toast(r.error,'error'); statusSet('error','error'); break; } await loadState(); await openCurrent(); toast('compacted — '+(r.result.chars||0)+' char summary','ok'); statusSet('ready'); break; }
    case 'palette': openPalette(); break;
    case 'find': openFind(); break;
    case 'search': case 'search-all': openSearch(); break;
    case 'shortcuts': case 'keys': openShortcuts(); break;
    case 'quit': toast('close the tab to quit'); break;
  }
}

// ---------- attachments ----------
let ATT=[];
function renderAtt(){ const box=$('attchips'); if(!box) return;
  box.innerHTML=ATT.map((a,i)=>'<span class="att">📎 '+esc(a.name)+' <b data-i="'+i+'" style="cursor:pointer">✕</b></span>').join('');
  box.querySelectorAll('b').forEach(b=>b.onclick=()=>{ ATT.splice(+b.dataset.i,1); renderAtt(); }); }
function readAs(file){ return new Promise((res,rej)=>{ const fr=new FileReader(); fr.onload=()=>res(fr.result); fr.onerror=rej; if(file.type.startsWith('image/')) fr.readAsDataURL(file); else fr.readAsText(file); }); }
$('clip').onclick=()=>{ const f=document.createElement('input'); f.type='file'; f.multiple=true;
  f.onchange=async()=>{ for(const file of f.files){ try{ const data=await readAs(file);
    if(file.type.startsWith('image/')) ATT.push({kind:'image',name:file.name,mime:file.type||'image/png',data:String(data).split(',')[1]||''});
    else ATT.push({kind:'text',name:file.name,mime:file.type||'text/plain',data:String(data)}); }catch(e){ toast('could not read '+file.name,'error'); } }
    renderAtt(); }; f.click(); };
async function toggleAgent(v){ const on=(typeof v==='boolean')?v:!STATE.agent; await api('/api/toggle',{agent:on}); await loadState(); toast('agent mode '+(on?'ON':'OFF')); }

// ---------- events ----------
(function(){ const tb=$('toolbar'); if(!tb) return;
  tb.querySelectorAll('.tb').forEach(el=>{ el.onclick=()=>{
    const c=el.dataset.cmd;
    if(c==='mode') runSlash(STATE&&STATE.mode==='plan'?'/build':'/plan'); else runSlash(c);
  }; });
})();
$('newSess').onclick=newSession;
$('graphBtn').onclick=openGraph;
$('agentchip').onclick=()=>toggleAgent();
$('sessSearch').oninput=renderSessions;
$('modelchip').onclick=openModels;
function panelVisible(sel){ const el=document.querySelector(sel); return !!el && getComputedStyle(el).display!=='none'; }
function togglePanel(sel, cls, btn){ const vis=panelVisible(sel);
  if(vis){ document.body.classList.remove('show'+cls); document.body.classList.add('no'+cls); }
  else { document.body.classList.add('show'+cls); document.body.classList.remove('no'+cls); }
  btn.classList.toggle('off', !panelVisible(sel)); }
function toggleSide(){ togglePanel('aside.side','side',$('tgSide')); }
function toggleInfo(){ togglePanel('aside.info','info',$('tgInfo')); }
$('tgSide').onclick=toggleSide;
$('tgInfo').onclick=toggleInfo;
$('jumpBtn').onclick=()=>{ STICK=true; const c=$('chat'); c.scrollTo({top:c.scrollHeight,behavior:'smooth'}); };
$('chat').addEventListener('scroll',()=>{ const c=$('chat'); STICK=c.scrollHeight-c.scrollTop-c.clientHeight<48; $('jumpBtn').classList.toggle('hidden',STICK); });
// Keep the view pinned to the newest message while more content renders in
// (markdown/code windows change the scroll height after the initial paint).
new MutationObserver(()=>{ if(STICK){ const c=$('chat'); if(c) c.scrollTop=c.scrollHeight; } })
  .observe($('chat'), {childList:true, subtree:true});
document.addEventListener('click',e=>{ const b=e.target.closest('[data-slash]'); if(b){ e.preventDefault(); runSlash(b.getAttribute('data-slash')); } });
const inp=$('inp');
function autosize(t){ t.style.height='auto'; t.style.height=Math.min(t.scrollHeight,180)+'px'; }
inp.addEventListener('input',()=>{ autosize(inp); updatePop(); });
inp.addEventListener('keydown',async e=>{
  if(POP_ROWS.length){
    if(e.key==='ArrowDown'){e.preventDefault();popMove(1);return;}
    if(e.key==='ArrowUp'){e.preventDefault();popMove(-1);return;}
    if(e.key==='Tab'){e.preventDefault();applyPop();return;}
    if(e.key==='Enter'){e.preventDefault();applyPop();return;}
    if(e.key==='Escape'){e.preventDefault();hidePop();return;}
  }
  if(e.key==='Enter'&&!e.shiftKey){ e.preventDefault(); await submitInput(); }
});
async function submitInput(){
  const v=inp.value.trim(); if(!v) return;
  if(v.startsWith('/')){ inp.value=''; autosize(inp); hidePop(); await runSlash(v); return; }
  inp.value=''; autosize(inp); hidePop();
  askNotifyPermission();
  if(v.startsWith('!')){ await runShell(v.slice(1).trim()); return; }
  const text=await resolveAt(v);
  const atts=ATT.splice(0,ATT.length); renderAtt();
  if(!(await guardCheck(text))) return;
  if(STATE&&STATE.agent) await sendAgent(text,atts); else await sendText(text,atts);
}
{ const sb=$('sendBtn'); if(sb) sb.onclick=()=>submitInput(); }
document.addEventListener('keydown',e=>{
  if(MODAL){ if(e.key==='Escape'){e.preventDefault();closeModal();} return; }
  if(OV){
    if(e.target===OV.filterEl){ if(e.key==='Escape'){e.preventDefault();closeOverlay();} else if(e.key==='Enter'){e.preventDefault();pickOv();} else if(e.key==='ArrowDown'){e.preventDefault();ovMove(1);} else if(e.key==='ArrowUp'){e.preventDefault();ovMove(-1);} return; }
    if(e.key==='ArrowDown'){e.preventDefault();ovMove(1);}
    else if(e.key==='ArrowUp'){e.preventDefault();ovMove(-1);}
    else if(e.key==='Enter'){e.preventDefault();pickOv();}
    else if(e.key==='Escape'){e.preventDefault();closeOverlay();}
    else if(OV.onKey&&OV.onKey(e)){ e.preventDefault(); }
    else if(e.key.length===1&&!e.ctrlKey&&!e.metaKey&&OV.filterEl){ OV.filterEl.focus(); }
    return;
  }
  const mod=e.ctrlKey||e.metaKey;
  if(mod&&e.key.toLowerCase()==='p'){e.preventDefault();openPalette();}
  else if(mod&&e.key.toLowerCase()==='s'){e.preventDefault();openSessions();}
  else if(mod&&e.key.toLowerCase()==='r'){e.preventDefault();openSearch();}
  else if(mod&&e.key.toLowerCase()==='f'){e.preventDefault();openFind();}
  else if(mod&&e.key.toLowerCase()==='k'){e.preventDefault();openSearch();}
  else if(mod&&e.key.toLowerCase()==='g'){e.preventDefault();openGraph();}
  else if(e.altKey&&e.key.toLowerCase()==='s'){e.preventDefault();toggleSide();}
  else if(e.altKey&&e.key.toLowerCase()==='i'){e.preventDefault();toggleInfo();}
});

// ---------- boot ----------
function setTheme(t){ document.body.dataset.theme=t; localStorage.setItem('enclave-theme',t); }
setTheme(localStorage.getItem('enclave-theme')||'default');
function syncPanelBtns(){ $('tgSide').classList.toggle('off', !panelVisible('aside.side')); $('tgInfo').classList.toggle('off', !panelVisible('aside.info')); }
window.addEventListener('resize', syncPanelBtns);
(async()=>{ await loadState(); if(STATE){ await openCurrent(); } ensureComposer(); syncPanelBtns(); statusSet('ready'); })();
</script>
</body>
</html>
"#;

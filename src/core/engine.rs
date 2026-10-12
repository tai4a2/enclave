//! The chat engine: ties a provider, the encrypted memory and a session together.

use std::collections::HashMap;
use std::path::PathBuf;

use async_trait::async_trait;

use crate::config::{Action, EgressAction, Permissions};
use crate::core::attachment::Attachment;
use crate::core::builtin_tools::{self, ToolContext};
use crate::core::message::{Message, ToolCall};
use crate::core::session::Session;
use crate::error::{EnclaveError, Result};
use crate::privacy::guard::{Redactor, redact_messages, redact_tainted};
use crate::privacy::keys::SecureCredentials;
use crate::privacy::memory::EncryptedMemory;
use crate::providers::{
    ChunkStream, Provider, ToolDef, create_provider, default_model_for, requires_api_key,
};

/// Lazily-created provider: avoids touching the OS keychain until the first
/// message is actually sent.
enum ProviderSlot {
    Ready(Box<dyn Provider>),
    Lazy {
        name: String,
        ollama_base_url: String,
    },
}

impl ProviderSlot {
    async fn get(&mut self) -> Result<&dyn Provider> {
        if let ProviderSlot::Lazy {
            name,
            ollama_base_url,
        } = self
        {
            let name = name.clone();
            let base_url = ollama_base_url.clone();
            let api_key = if requires_api_key(&name) {
                let var = format!("ENCLAVE_{}_API_KEY", name.to_ascii_uppercase());
                Some(SecureCredentials::local_api_key(&name).ok_or_else(|| {
                    EnclaveError::auth(format!(
                        "no API key for '{name}' — run `enclave keys set {name}` or export {var}"
                    ))
                })?)
            } else {
                None
            };
            let provider = create_provider(&name, api_key, &base_url)?;
            *self = ProviderSlot::Ready(provider);
        }
        match self {
            ProviderSlot::Ready(p) => Ok(&**p),
            ProviderSlot::Lazy { .. } => unreachable!("slot was just materialized"),
        }
    }
}

/// What the approval UI decided for a proposed tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolDecision {
    Approve,
    Deny,
    /// Approve this one and all remaining calls of the current turn.
    ApproveAll,
    /// Abort the whole turn (no further calls, no further requests).
    Stop,
}

/// UI callback surface used while the agentic loop runs.
#[async_trait]
pub trait ToolGate: Send {
    /// Show the call and ask for a decision (ask-always by default).
    async fn decide(&mut self, call: &ToolCall) -> ToolDecision;
    /// Show the executed result.
    async fn observe(&mut self, call: &ToolCall, output: &str);
}

/// A gate that approves everything — for UIs that already collected consent
/// (e.g. the TUI confirms each call itself before executing).
pub struct ApprovedGate;

#[async_trait]
impl ToolGate for ApprovedGate {
    async fn decide(&mut self, _call: &ToolCall) -> ToolDecision {
        ToolDecision::Approve
    }
    async fn observe(&mut self, _call: &ToolCall, _output: &str) {}
}

/// One step of an event-driven agentic turn (for interactive UIs).
pub enum AgentStep {
    /// The assistant produced a final answer (no tool calls).
    Final(String),
    /// The assistant asked to run tools: the caller approves/executes them and
    /// feeds the results back via [`ChatEngine::push_tool_result`], then calls
    /// [`ChatEngine::agentic_step`] again.
    ToolCalls {
        text: String,
        calls: Vec<ToolCall>,
    },
}

/// Operating mode of the engine (opencode-style Plan/Build).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AgentMode {
    /// Full access (subject to the permission policy).
    #[default]
    Build,
    /// Read-only: mutating tools are refused and the model is told to plan.
    Plan,
}

impl AgentMode {
    pub fn label(self) -> &'static str {
        match self {
            AgentMode::Build => "build",
            AgentMode::Plan => "plan",
        }
    }

    pub fn is_plan(self) -> bool {
        matches!(self, AgentMode::Plan)
    }
}

fn is_mutating_tool(name: &str) -> bool {
    matches!(name, "write_file" | "edit_file" | "run_shell" | "delegate")
}

/// Orchestrates a conversation turn by turn.
pub struct ChatEngine {
    provider: ProviderSlot,
    provider_name: &'static str,
    pub model: String,
    pub memory: EncryptedMemory,
    pub session: Session,
    pub system_prompt: Option<String>,
    /// When set, every outgoing message (except the system prompt) is
    /// redacted with stable placeholders before reaching the provider.
    /// The stored history keeps the original (encrypted at rest).
    pub redactor: Option<Redactor>,
    /// Optional reasoning effort hint (`low`/`medium`/`high`).
    pub reasoning_effort: Option<String>,
    /// Local rules text (AGENTS.md-style) appended to the system prompt.
    pub rules: Option<String>,
    /// Permission policy for tool calls.
    pub permissions: Permissions,
    /// Plan (read-only) or Build mode.
    pub mode: AgentMode,
    /// Workspace root: file tools cannot escape it.
    pub workspace: PathBuf,
    /// Task list the model maintains via the `todo` tool (shown in the UI).
    pub todos: std::sync::Arc<std::sync::Mutex<Vec<builtin_tools::TodoItem>>>,
    /// Connected MCP servers and their tools, if configured.
    pub mcp: Option<std::sync::Arc<crate::core::mcp::McpRegistry>>,
    /// Persistent memories injected into the system prompt (never `local_only`).
    pub memories: Vec<crate::privacy::Memory>,
    /// Taint tracking: mark user messages that contain sensitive data and
    /// re-redact them automatically on later turns.
    pub taint: bool,
    /// Data-egress policy (policy-as-code), enforced on remote providers only.
    pub policy: Option<crate::privacy::policy::Policy>,
}

impl ChatEngine {
    pub fn new(
        provider: Box<dyn Provider>,
        model: String,
        memory: EncryptedMemory,
        session: Session,
        system_prompt: Option<String>,
    ) -> Self {
        let provider_name = provider.name();
        ChatEngine {
            provider: ProviderSlot::Ready(provider),
            provider_name,
            model,
            memory,
            session,
            system_prompt,
            redactor: None,
            reasoning_effort: None,
            rules: None,
            permissions: Permissions::default(),
            mode: AgentMode::Build,
            workspace: std::env::current_dir().unwrap_or_default(),

            todos: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            mcp: None,
            memories: Vec::new(),
            taint: true,
            policy: None,
        }
    }

    /// Build an engine that creates its provider (and reads the API key from
    /// the keychain) only when the first message is sent.
    pub fn lazy(
        provider_name: &str,
        ollama_base_url: String,
        model: Option<String>,
        memory: EncryptedMemory,
        session: Session,
        system_prompt: Option<String>,
    ) -> Result<Self> {
        let canonical = crate::providers::known_providers()
            .iter()
            .copied()
            .find(|p| *p == provider_name)
            .ok_or_else(|| {
                EnclaveError::provider(format!(
                    "unknown provider '{provider_name}' (known: {})",
                    crate::providers::known_providers().join(", ")
                ))
            })?;
        let model = model.unwrap_or_else(|| {
            default_model_for(canonical)
                .unwrap_or("unknown")
                .to_string()
        });
        Ok(ChatEngine {
            provider: ProviderSlot::Lazy {
                name: canonical.to_string(),
                ollama_base_url,
            },
            provider_name: canonical,
            model,
            memory,
            session,
            system_prompt,
            redactor: None,
            reasoning_effort: None,
            rules: None,
            permissions: Permissions::default(),
            mode: AgentMode::Build,
            workspace: std::env::current_dir().unwrap_or_default(),

            todos: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            mcp: None,
            memories: Vec::new(),
            taint: true,
            policy: None,
        })
    }

    /// Provider name.
    pub fn provider_name(&self) -> &'static str {
        self.provider_name
    }

    /// Reload the persistent memories that get injected into the system prompt.
    pub fn reload_memories(&mut self) -> Result<()> {
        self.memories = self.memory.injectable_memories(50)?;
        Ok(())
    }

    /// Execute a tool call that needs engine state (currently `remember`),
    /// returning `Some(result)` when handled. Callers fall through to
    /// `builtin_tools::execute` when this returns `None`.
    pub fn execute_stateful(&mut self, call: &ToolCall) -> Option<Result<String>> {
        match call.name.as_str() {
            "remember" => {
                let args: serde_json::Value = serde_json::from_str(&call.arguments)
                    .unwrap_or_else(|_| serde_json::json!({}));
                let text = args["text"].as_str().unwrap_or("").trim().to_string();
                if text.is_empty() {
                    return Some(Err(EnclaveError::other("remember: 'text' is required")));
                }
                let tags = args["tags"].as_str().unwrap_or("").to_string();
                let local_only = args["local_only"].as_bool().unwrap_or(false);
                let sid = self.session.id.clone();
                let out = (|| -> Result<String> {
                    let id = self
                        .memory
                        .add_memory(&text, &tags, "note", Some(&sid), local_only)?;
                    self.reload_memories()?;
                    Ok(format!("remembered [{}] {}", &id[..8.min(id.len())], text))
                })();
                Some(out)
            }
            _ => None,
        }
    }

    /// Built-in tool definitions plus any dynamically discovered MCP tools.
    pub fn tool_defs(&self, with_delegate: bool) -> Vec<ToolDef> {
        let mut defs = builtin_tools::defs(with_delegate);
        if let Some(mcp) = &self.mcp {
            defs.extend(mcp.defs());
        }
        defs
    }

    /// Combine the configured system prompt, local rules and the Plan-mode
    /// note into a single system message (or `None`).
    pub fn system_text(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        if let Some(sp) = &self.system_prompt {
            parts.push(sp.clone());
        }
        if let Some(rules) = &self.rules {
            parts.push(rules.clone());
        }
        if self.mode.is_plan() {
            parts.push(
                "You are in PLAN mode: analyse the request and propose a clear \
                 step-by-step plan. Do not modify files or run mutating commands."
                    .to_string(),
            );
        }
        if !self.memories.is_empty() {
            let mut block =
                String::from("# Memory (persistent facts and preferences to remember)\n");
            for m in &self.memories {
                block.push_str("- ");
                block.push_str(&m.text);
                let tags = m.tags.trim();
                if !tags.is_empty() {
                    block.push_str(" (tags: ");
                    block.push_str(tags);
                    block.push(')');
                }
                block.push('\n');
            }
            parts.push(block.trim_end().to_string());
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join("\n\n"))
        }
    }

    /// Build the message list sent to the provider (system prompt + history).
    pub fn request_messages(&self) -> Vec<Message> {
        let mut msgs: Vec<Message> = Vec::new();
        if let Some(sp) = self.system_text() {
            msgs.push(Message::system(sp));
        }
        msgs.extend(self.session.messages.iter().cloned());
        msgs
    }

    /// Enforce the data-egress policy for a remote provider. Local providers
    /// (Ollama) are never restricted. `Block` refuses the send; `Redact`
    /// activates the redactor so `outgoing_messages` replaces the values.
    fn apply_egress_policy(&mut self) -> Result<()> {
        let Some(policy) = self.policy.clone() else {
            return Ok(());
        };
        if !crate::providers::requires_api_key(self.provider_name()) {
            return Ok(());
        }
        let msgs = self.request_messages();
        let mut findings = Vec::new();
        for m in &msgs {
            findings.extend(crate::privacy::guard::scan(&m.content));
            for a in &m.attachments {
                if a.kind == crate::core::attachment::AttachmentKind::Text {
                    findings.extend(crate::privacy::guard::scan(&a.data));
                }
            }
        }
        match policy.decide(&findings) {
            EgressAction::Allow => Ok(()),
            EgressAction::Redact => {
                if self.redactor.is_none() {
                    self.redactor = Some(Redactor::new());
                }
                Ok(())
            }
            EgressAction::Block => Err(EnclaveError::other(format!(
                "egress blocked by policy: {} sensitive item(s) detected (see [policy] in config.toml)",
                findings.len()
            ))),
        }
    }

    /// Build the outgoing request, applying privacy-guard redaction when active.
    pub fn outgoing_messages(&mut self) -> Vec<Message> {
        let skip_system = self.system_text().is_some();
        let mut msgs = self.request_messages();
        if let Some(r) = &mut self.redactor {
            redact_messages(&mut msgs, r, skip_system);
        } else if self.taint && msgs.iter().any(|m| m.tainted) {
            // Taint tracking: a message that once carried sensitive data is
            // re-redacted automatically on later turns (no prompt needed).
            let mut r = Redactor::new();
            redact_tainted(&mut msgs, &mut r, skip_system);
            self.redactor = Some(r);
        }
        msgs
    }

    /// Push a user message, flagging it as tainted when taint tracking is on
    /// and the content (or a text attachment) contains sensitive data.
    fn push_user(&mut self, input: &str, attachments: Vec<Attachment>) -> Result<()> {
        let mut sensitive = crate::privacy::guard::has_sensitive_data(input);
        if !sensitive {
            for a in &attachments {
                if a.kind == crate::core::attachment::AttachmentKind::Text
                    && crate::privacy::guard::has_sensitive_data(&a.data)
                {
                    sensitive = true;
                    break;
                }
            }
        }
        let mut m = Message::user_with_attachments(input, attachments);
        m.tainted = self.taint && sensitive;
        self.session.push(m, &self.memory)
    }

    /// Record an outbound request in the encrypted egress ledger (best-effort:
    /// never blocks a send). Stores only a fingerprint and the redaction summary.
    pub fn record_egress(&mut self, messages: &[Message]) -> Result<()> {
        let payload = serde_json::to_vec(messages).unwrap_or_default();
        let redactions = self
            .redactor
            .as_ref()
            .map(|r| r.summary())
            .unwrap_or_default();
        self.memory.add_egress(
            Some(&self.session.id),
            self.provider_name(),
            &self.model,
            &payload,
            &redactions,
        )
    }

    /// Effective permission for a tool call: Plan mode refuses mutations, the
    /// `external_directory` rule tightens out-of-workspace paths, and `auto`
    /// turns `ask` into `allow` (denied tools stay denied).
    pub fn effective_action(&self, call: &ToolCall) -> Action {
        if self.mode.is_plan() && is_mutating_tool(&call.name) {
            return Action::Deny;
        }
        let external = crate::core::permissions::call_is_external(call, &self.workspace);
        let mut action = crate::core::permissions::resolve(&self.permissions, call, external);
        if action == Action::Ask && self.permissions.auto {
            action = Action::Allow;
        }
        action
    }

    /// Persist the user's input and start streaming the assistant reply.
    pub async fn stream_reply(&mut self, input: &str) -> Result<ChunkStream> {
        self.stream_reply_with(input, Vec::new()).await
    }

    /// Persist the user's input (with file attachments) and start streaming.
    pub async fn stream_reply_with(
        &mut self,
        input: &str,
        attachments: Vec<Attachment>,
    ) -> Result<ChunkStream> {
        self.push_user(input, attachments)?;
        self.apply_egress_policy()?;
        let messages = self.outgoing_messages();
        let _ = self.record_egress(&messages);
        let model = self.model.clone();
        let effort = self.reasoning_effort.clone();
        let provider = self.provider.get().await?;
        provider.chat_stream(messages, &model, effort.as_deref()).await
    }

    /// Persist a completed assistant reply.
    pub fn commit_assistant(&mut self, content: String) -> Result<()> {
        self.session.add_assistant(&self.memory, &content)
    }

    /// Run one full agentic turn: request → tool calls → approval → results
    /// → repeat, until the assistant produces a final text answer.
    ///
    /// Every tool call passes through `gate` (nothing auto-runs). Tool
    /// results are capped by the context, encrypted at rest and redacted
    /// on the way out like any other message.
    pub async fn turn_agentic(
        &mut self,
        input: &str,
        defs: &[ToolDef],
        ctx: &ToolContext,
        gate: &mut dyn ToolGate,
        max_iterations: usize,
    ) -> Result<String> {
        self.turn_agentic_with(input, Vec::new(), defs, ctx, gate, max_iterations)
            .await
    }

    /// Like [`ChatEngine::turn_agentic`], with file attachments on the first
    /// user message.
    pub async fn turn_agentic_with(
        &mut self,
        input: &str,
        attachments: Vec<Attachment>,
        defs: &[ToolDef],
        ctx: &ToolContext,
        gate: &mut dyn ToolGate,
        max_iterations: usize,
    ) -> Result<String> {
        self.push_user(input, attachments)?;
        let mut approve_all = false;
        let mut seen: HashMap<String, u32> = HashMap::new();

        for _ in 0..max_iterations.max(1) {
            self.apply_egress_policy()?;
            let messages = self.outgoing_messages();
            let _ = self.record_egress(&messages);
            let model = self.model.clone();
            let effort = self.reasoning_effort.clone();
            let response = self
                .provider
                .get()
                .await?
                .chat_with_tools(messages, &model, defs, effort.as_deref())
                .await?;

            if response.tool_calls.is_empty() {
                self.session
                    .push(Message::assistant(response.text.clone()), &self.memory)?;
                return Ok(response.text);
            }

            self.session.push(
                Message::assistant_with_tool_calls(response.text.clone(), response.tool_calls.clone()),
                &self.memory,
            )?;

            for call in &response.tool_calls {
                // Permission policy (with a doom-loop guard for repeats).
                let key = format!("{}\u{0}{}", call.name, call.arguments);
                let count = seen.entry(key).or_insert(0);
                *count += 1;
                let mut action = self.effective_action(call);
                if *count >= 3 {
                    if let Some(dl) = self.permissions.doom_loop {
                        action = crate::core::permissions::combine(action, dl);
                    }
                }

                let decision = match action {
                    Action::Allow => ToolDecision::Approve,
                    Action::Deny => ToolDecision::Deny,
                    Action::Ask => {
                        if approve_all {
                            ToolDecision::Approve
                        } else {
                            match gate.decide(call).await {
                                ToolDecision::ApproveAll => {
                                    approve_all = true;
                                    ToolDecision::Approve
                                }
                                other => other,
                            }
                        }
                    }
                };

                let output = match decision {
                    ToolDecision::Stop => {
                        self.session
                            .push(Message::tool_result(&call.id, "[stopped by user]"), &self.memory)?;
                        return Ok(String::new());
                    }
                    ToolDecision::Deny => {
                        if action == Action::Deny {
                            "[denied by policy]".to_string()
                        } else {
                            "[denied by user]".to_string()
                        }
                    }
                    ToolDecision::Approve => match self.execute_stateful(call) {
                        Some(Ok(out)) => out,
                        Some(Err(e)) => format!("[tool error] {e}"),
                        None => match builtin_tools::execute(call, ctx, gate).await {
                            Ok(out) => out,
                            Err(e) => format!("[tool error] {e}"),
                        },
                    },
                    ToolDecision::ApproveAll => unreachable!("converted above"),
                };

                gate.observe(call, &output).await;
                self.session
                    .push(Message::tool_result(&call.id, output), &self.memory)?;
            }
        }

        Err(EnclaveError::other(format!(
            "tool loop did not converge within {max_iterations} iterations"
        )))
    }

    // ---- Event-driven stepping API (used by the TUI) ----------------------

    /// Persist the user's input and prepare an event-driven agentic turn.
    pub fn begin_agentic(&mut self, input: &str) -> Result<()> {
        self.begin_agentic_with(input, Vec::new())
    }

    /// Persist the user's input (with attachments) and prepare an agentic turn.
    pub fn begin_agentic_with(&mut self, input: &str, attachments: Vec<Attachment>) -> Result<()> {
        self.push_user(input, attachments)
    }

    /// Ask the provider for the next step. Returns either a final answer or a
    /// set of tool calls awaiting the caller's decision.
    pub async fn agentic_step(&mut self, defs: &[ToolDef]) -> Result<AgentStep> {
        self.apply_egress_policy()?;
        let messages = self.outgoing_messages();
        let _ = self.record_egress(&messages);
        let model = self.model.clone();
        let effort = self.reasoning_effort.clone();
        let response = {
            let provider = self.provider.get().await?;
            provider
                .chat_with_tools(messages, &model, defs, effort.as_deref())
                .await?
        };

        if response.tool_calls.is_empty() {
            self.session
                .push(Message::assistant(response.text.clone()), &self.memory)?;
            Ok(AgentStep::Final(response.text))
        } else {
            self.session.push(
                Message::assistant_with_tool_calls(
                    response.text.clone(),
                    response.tool_calls.clone(),
                ),
                &self.memory,
            )?;
            Ok(AgentStep::ToolCalls {
                text: response.text,
                calls: response.tool_calls,
            })
        }
    }

    /// Feed a tool result back into the conversation and continue the turn.
    pub fn push_tool_result(&mut self, call_id: &str, output: &str) -> Result<()> {
        self.session
            .push(Message::tool_result(call_id, output), &self.memory)
    }

    /// Remove the last turn (the trailing assistant/tool messages plus the
    /// user message that started it) and return the user text so it can be
    /// re-sent or edited. Returns `None` when there is nothing to undo.
    pub fn undo_last_turn(&mut self) -> Result<Option<String>> {
        let last_user = self
            .session
            .messages
            .iter()
            .rposition(|m| m.role == crate::core::message::Role::User);
        let Some(idx) = last_user else {
            return Ok(None);
        };
        let text = self.session.messages[idx].content.clone();
        self.session.truncate_to(&self.memory, idx)?;
        Ok(Some(text))
    }

    /// Drop the trailing assistant/tool messages after the last user message
    /// and return that user text so the reply can be regenerated. Returns
    /// `None` when there is no user message.
    pub fn retry_last(&mut self) -> Result<Option<String>> {
        let Some(idx) = self
            .session
            .messages
            .iter()
            .rposition(|m| m.role == crate::core::message::Role::User)
        else {
            return Ok(None);
        };
        self.session.truncate_to(&self.memory, idx + 1)?;
        Ok(Some(self.session.messages[idx].content.clone()))
    }

    /// Summarise the conversation with the provider and replace the history
    /// with that summary (reduces the context sent on later turns).
    pub async fn compact(&mut self) -> Result<String> {
        let mut msgs = self.request_messages();
        msgs.push(Message::user(
            "Summarise the conversation above for your own future reference. \
             Keep the key facts, decisions, file paths and open questions. \
             Be concise; reply with the summary only.",
        ));
        let model = self.model.clone();
        let effort = self.reasoning_effort.clone();
        let summary = {
            let provider = self.provider.get().await?;
            provider.chat(msgs, &model, effort.as_deref()).await?
        };
        self.session.compact_with(&self.memory, &summary)?;
        Ok(summary)
    }

    /// Send a single prompt without touching the session history and return the
    /// model's text reply. Used for utility tasks such as `/init`.
    pub async fn one_shot(&mut self, prompt: &str) -> Result<String> {
        let messages = vec![Message::user(prompt)];
        let model = self.model.clone();
        let effort = self.reasoning_effort.clone();
        let response = {
            let provider = self.provider.get().await?;
            provider
                .chat_with_tools(messages, &model, &[], effort.as_deref())
                .await?
        };
        Ok(response.text)
    }

    /// Send the current conversation plus an instruction and return the model's
    /// text reply, without persisting anything. Used by `/checkpoint`.
    pub async fn summarize(&mut self, instruction: &str) -> Result<String> {
        let mut msgs = self.request_messages();
        msgs.push(Message::user(instruction));
        let model = self.model.clone();
        let effort = self.reasoning_effort.clone();
        let text = {
            let provider = self.provider.get().await?;
            provider.chat(msgs, &model, effort.as_deref()).await?
        };
        Ok(text)
    }
}
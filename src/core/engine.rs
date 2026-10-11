//! The chat engine: ties a provider, the encrypted memory and a session together.

use std::collections::HashMap;
use std::path::PathBuf;

use async_trait::async_trait;

use crate::config::{Action, Permissions};
use crate::core::attachment::Attachment;
use crate::core::builtin_tools::{self, ToolContext};
use crate::core::message::{Message, ToolCall};
use crate::core::session::Session;
use crate::error::{EnclaveError, Result};
use crate::privacy::guard::{Redactor, redact_messages};
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
        })
    }

    /// Provider name.
    pub fn provider_name(&self) -> &'static str {
        self.provider_name
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

    /// Build the outgoing request, applying privacy-guard redaction when active.
    pub fn outgoing_messages(&mut self) -> Vec<Message> {
        let skip_system = self.system_text().is_some();
        let mut msgs = self.request_messages();
        if let Some(r) = &mut self.redactor {
            redact_messages(&mut msgs, r, skip_system);
        }
        msgs
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
        self.session
            .push(Message::user_with_attachments(input, attachments), &self.memory)?;
        let messages = self.outgoing_messages();
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
        self.session
            .push(Message::user_with_attachments(input, attachments), &self.memory)?;
        let mut approve_all = false;
        let mut seen: HashMap<String, u32> = HashMap::new();

        for _ in 0..max_iterations.max(1) {
            let messages = self.outgoing_messages();
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
                    ToolDecision::Approve => match builtin_tools::execute(call, ctx, gate).await {
                        Ok(out) => out,
                        Err(e) => format!("[tool error] {e}"),
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
        self.session
            .push(Message::user_with_attachments(input, attachments), &self.memory)
    }

    /// Ask the provider for the next step. Returns either a final answer or a
    /// set of tool calls awaiting the caller's decision.
    pub async fn agentic_step(&mut self, defs: &[ToolDef]) -> Result<AgentStep> {
        let messages = self.outgoing_messages();
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
}
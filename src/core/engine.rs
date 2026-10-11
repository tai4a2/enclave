//! The chat engine: ties a provider, the encrypted memory and a session together.

use async_trait::async_trait;

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
        })
    }

    /// Provider name.
    pub fn provider_name(&self) -> &'static str {
        self.provider_name
    }

    /// Build the message list sent to the provider (system prompt + history).
    pub fn request_messages(&self) -> Vec<Message> {
        let mut msgs: Vec<Message> = Vec::new();
        if let Some(sp) = &self.system_prompt {
            msgs.push(Message::system(sp.clone()));
        }
        msgs.extend(self.session.messages.iter().cloned());
        msgs
    }

    /// Build the outgoing request, applying privacy-guard redaction when active.
    pub fn outgoing_messages(&mut self) -> Vec<Message> {
        let skip_system = self.system_prompt.is_some();
        let mut msgs = self.request_messages();
        if let Some(r) = &mut self.redactor {
            redact_messages(&mut msgs, r, skip_system);
        }
        msgs
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
                let decision = if approve_all {
                    ToolDecision::Approve
                } else {
                    match gate.decide(call).await {
                        ToolDecision::ApproveAll => {
                            approve_all = true;
                            ToolDecision::Approve
                        }
                        other => other,
                    }
                };

                let output = match decision {
                    ToolDecision::Stop => {
                        self.session
                            .push(Message::tool_result(&call.id, "[stopped by user]"), &self.memory)?;
                        return Ok(String::new());
                    }
                    ToolDecision::Deny => "[denied by user]".to_string(),
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
}
//! The chat engine: ties a provider, the encrypted memory and a session together.

use async_trait::async_trait;

use crate::core::builtin_tools::{self, ToolContext};
use crate::core::message::{Message, ToolCall};
use crate::core::session::Session;
use crate::error::{EnclaveError, Result};
use crate::privacy::guard::{Redactor, redact_messages};
use crate::privacy::memory::EncryptedMemory;
use crate::providers::{ChunkStream, Provider, ToolDef};

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

/// Orchestrates a conversation turn by turn.
pub struct ChatEngine {
    pub provider: Box<dyn Provider>,
    pub model: String,
    pub memory: EncryptedMemory,
    pub session: Session,
    pub system_prompt: Option<String>,
    /// When set, every outgoing message (except the system prompt) is
    /// redacted with stable placeholders before reaching the provider.
    /// The stored history keeps the original (encrypted at rest).
    pub redactor: Option<Redactor>,
}

impl ChatEngine {
    pub fn new(
        provider: Box<dyn Provider>,
        model: String,
        memory: EncryptedMemory,
        session: Session,
        system_prompt: Option<String>,
    ) -> Self {
        ChatEngine {
            provider,
            model,
            memory,
            session,
            system_prompt,
            redactor: None,
        }
    }

    /// Provider name.
    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
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
        self.session.add_user(&self.memory, input)?;
        let messages = self.outgoing_messages();
        self.provider.chat_stream(messages, &self.model).await
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
        self.session.push(Message::user(input), &self.memory)?;
        let mut approve_all = false;

        for _ in 0..max_iterations.max(1) {
            let messages = self.outgoing_messages();
            let response = self
                .provider
                .chat_with_tools(messages, &self.model, defs)
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
}
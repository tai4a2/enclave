//! Multi-agent support: personas + the `delegate` tool.
//!
//! A persona is a named sub-agent configuration (provider/model/system
//! prompt) declared in `config.toml`. The top-level agent can delegate a
//! task via the `delegate` tool; the sub-agent runs with its own provider,
//! its own ephemeral encrypted session (RAM only) and its own tool set —
//! but WITHOUT the `delegate` tool itself, so delegation is depth-limited.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::{Settings, ToolsMode};
use crate::core::engine::{ToolGate, ToolDecision};
use crate::core::builtin_tools::{self, DelegateFn, ToolContext};
use crate::core::engine::ChatEngine;
use crate::core::message::ToolCall;
use crate::core::session::Session;
use crate::error::{EnclaveError, Result};
use crate::privacy::crypto;
use crate::privacy::keys::SecureCredentials;
use crate::privacy::memory::EncryptedMemory;
use crate::privacy::vault::MasterKey;
use crate::providers::{create_provider, requires_api_key, ToolDef};

/// One configured sub-agent persona.
#[derive(Debug, Clone)]
pub struct Persona {
    pub name: String,
    pub provider: String,
    pub model: Option<String>,
    pub system_prompt: String,
}

/// Runs the built-in tool set, including `delegate`.
pub struct AgentRunner {
    pub personas: Vec<Persona>,
    pub default_provider: String,
    pub ollama_base_url: String,
    pub workspace: PathBuf,
    pub timeout_secs: u64,
    pub max_output_bytes: usize,
    pub mode: ToolsMode,
}

impl AgentRunner {
    pub fn from_settings(settings: &Settings) -> Self {
        let personas: Vec<Persona> = settings
            .agent
            .personas
            .iter()
            .map(|(name, p)| Persona {
                name: name.clone(),
                provider: p.provider.clone().unwrap_or_else(|| settings.default_provider.clone()),
                model: p.model.clone(),
                system_prompt: p.system_prompt.clone().unwrap_or_else(|| {
                    "You are a focused sub-agent. Complete the delegated task and \
                     report the result concisely."
                        .to_string()
                }),
            })
            .collect();
        Self {
            personas,
            default_provider: settings.default_provider.clone(),
            ollama_base_url: settings.ollama_base_url.clone(),
            workspace: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            timeout_secs: settings.tools.timeout_secs,
            max_output_bytes: settings.tools.max_output_bytes,
            mode: settings.tools.mode,
        }
    }

    /// Tool definitions for the top-level agent (delegate only if personas exist).
    pub fn defs(&self) -> Vec<ToolDef> {
        builtin_tools::defs(!self.personas.is_empty())
    }

    /// Tool definitions for sub-agents (never delegate: depth limit).
    fn sub_defs(&self) -> Vec<ToolDef> {
        builtin_tools::defs(false)
    }

    /// Build the `ToolContext` for the top-level agent, wiring the delegate
    /// closure to the configured personas.
    pub fn context(self: &Arc<Self>) -> ToolContext {
        let runner = Arc::clone(self);
        let delegate: Option<DelegateFn> = if self.personas.is_empty() {
            None
        } else {
            Some(Box::new(move |agent, task, gate| {
                let runner = Arc::clone(&runner);
                Box::pin(async move { runner.delegate_by_name(agent, task, gate).await })
            }))
        };
        ToolContext {
            workspace: self.workspace.clone(),
            shell_timeout_secs: self.timeout_secs,
            max_output_bytes: self.max_output_bytes,
            delegate,
        }
    }

    /// Context for sub-agents: same sandbox, no delegation.
    fn sub_context(&self) -> ToolContext {
        ToolContext {
            workspace: self.workspace.clone(),
            shell_timeout_secs: self.timeout_secs,
            max_output_bytes: self.max_output_bytes,
            delegate: None,
        }
    }

    /// Run a sub-agent persona on `task` and return its final answer.
    async fn delegate_by_name(
        &self,
        agent: &str,
        task: &str,
        gate: &mut dyn ToolGate,
    ) -> Result<String> {
        let persona = self.personas.iter().find(|p| p.name == agent).ok_or_else(|| {
            EnclaveError::other(format!(
                "unknown agent '{agent}' (configured: {})",
                self.personas.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", ")
            ))
        })?;

        let api_key = if requires_api_key(&persona.provider) {
            Some(SecureCredentials::local_api_key(&persona.provider).ok_or_else(|| {
                EnclaveError::auth(format!(
                    "no API key for provider '{}' (agent '{agent}') — run `enclave keys set {}`",
                    persona.provider, persona.provider
                ))
            })?)
        } else {
            None
        };
        let provider = create_provider(&persona.provider, api_key, &self.ollama_base_url)?;
        let model = persona
            .model
            .clone()
            .unwrap_or_else(|| provider.default_model().to_string());

        // Ephemeral encrypted RAM store: the sub-agent conversation never
        // touches disk and never enters the main session.
        let key = MasterKey::from_bytes(crypto::random_key());
        let memory = EncryptedMemory::open_ephemeral(&key)?;
        let session = Session::ephemeral(&format!("agent:{agent}"));
        let mut engine =
            ChatEngine::new(provider, model, memory, session, Some(persona.system_prompt.clone()));

        let defs = self.sub_defs();
        let ctx = self.sub_context();
        engine
            .turn_agentic(task, &defs, &ctx, gate, 6)
            .await
    }

    /// Convenience for tests / direct use: run one tool call synchronously.
    pub async fn run_call(
        &self,
        call: &ToolCall,
        ctx: &ToolContext,
        gate: &mut dyn ToolGate,
    ) -> Result<String> {
        let _ = self;
        builtin_tools::execute(call, ctx, gate).await
    }
}

/// Approve/deny map used by tests and headless runs.
#[derive(Default)]
pub struct AutoGate {
    pub approve_all: bool,
    pub decisions: Vec<(String, ToolDecision)>,
}

#[async_trait::async_trait]
impl ToolGate for AutoGate {
    async fn decide(&mut self, call: &ToolCall) -> ToolDecision {
        let d = if self.approve_all {
            ToolDecision::ApproveAll
        } else {
            ToolDecision::Deny
        };
        self.decisions.push((call.name.clone(), d));
        d
    }

    async fn observe(&mut self, _call: &ToolCall, _output: &str) {}
}

/// personas lookup used by cli when building the runner.
pub fn persona_map(settings: &Settings) -> &BTreeMap<String, crate::config::PersonaSettings> {
    &settings.agent.personas
}
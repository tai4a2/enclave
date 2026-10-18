//! Provider abstraction and registry.

use std::pin::Pin;

use async_trait::async_trait;
use futures::Stream;

use crate::core::message::Message;
use crate::error::{EnclaveError, Result};

pub mod anthropic;
pub mod http;
pub mod ollama;
pub mod openai;
pub mod openai_compat;
pub mod openrouter;

pub use anthropic::AnthropicProvider;
pub use ollama::OllamaProvider;
pub use openai::OpenAIProvider;
pub use openrouter::{OpenRouterAccount, OpenRouterModel, OpenRouterProvider};

/// A stream of text chunks produced by a provider.
pub type ChunkStream = Pin<Box<dyn Stream<Item = Result<String>> + Send>>;

/// A tool the assistant may call (JSON-Schema `parameters`).
#[derive(Debug, Clone)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

impl ToolDef {
    pub fn new(name: &str, description: &str, parameters: serde_json::Value) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            parameters,
        }
    }
}

/// Result of a non-streaming turn that may contain tool calls.
#[derive(Debug, Clone)]
pub struct ToolResponse {
    /// Any text the assistant produced alongside/before the calls.
    pub text: String,
    /// Tool calls requested by the assistant (possibly empty).
    pub tool_calls: Vec<crate::core::message::ToolCall>,
}

/// A chat completion backend.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Stable provider name (matches the registry key).
    fn name(&self) -> &'static str;

    /// Suggested default model for this provider.
    fn default_model(&self) -> &'static str;

    /// Start a streaming chat completion.
    ///
    /// `effort` is an optional reasoning effort hint (`low`/`medium`/`high`);
    /// providers that support it include it in the request, others ignore it.
    async fn chat_stream(
        &self,
        messages: Vec<Message>,
        model: &str,
        effort: Option<&str>,
    ) -> Result<ChunkStream>;

    /// Non-streaming turn with function-calling support.
    ///
    /// Default implementation ignores tools (plain completion); providers
    /// with function-calling support override this.
    async fn chat_with_tools(
        &self,
        messages: Vec<Message>,
        model: &str,
        tools: &[ToolDef],
        effort: Option<&str>,
    ) -> Result<ToolResponse> {
        let _ = tools;
        Ok(ToolResponse {
            text: self.chat(messages, model, effort).await?,
            tool_calls: Vec::new(),
        })
    }

    /// Convenience: collect a full (non-streaming) completion.
    async fn chat(
        &self,
        messages: Vec<Message>,
        model: &str,
        effort: Option<&str>,
    ) -> Result<String> {
        use futures::StreamExt;
        let mut stream = self.chat_stream(messages, model, effort).await?;
        let mut out = String::new();
        while let Some(chunk) = stream.next().await {
            out.push_str(&chunk?);
        }
        Ok(out)
    }
}

/// List of provider names supported out of the box.
pub fn known_providers() -> &'static [&'static str] {
    &["openrouter", "openai", "anthropic", "ollama"]
}

/// Providers that require an API key (everything except local Ollama).
pub fn requires_api_key(name: &str) -> bool {
    name != "ollama"
}

/// Suggested default model for a provider name, without building it.
pub fn default_model_for(name: &str) -> Option<&'static str> {
    Some(match name {
        "openrouter" => "mistralai/mistral-large-4-0",
        "openai" => "gpt-4o-mini",
        "anthropic" => "claude-3-5-sonnet-latest",
        "ollama" => "llama3.1",
        _ => return None,
    })
}

/// Static, offline model suggestions for providers without a public catalogue.
///
/// OpenRouter returns an empty list here: its catalogue is fetched live.
pub fn suggested_models(name: &str) -> Vec<&'static str> {
    match name {
        "openai" => vec![
            "gpt-4o-mini",
            "gpt-4o",
            "gpt-4.1-mini",
            "gpt-4.1",
            "o4-mini",
        ],
        "anthropic" => vec![
            "claude-3-5-sonnet-latest",
            "claude-3-5-haiku-latest",
            "claude-3-opus-latest",
        ],
        "ollama" => vec![
            "llama3.1",
            "llama3.2",
            "qwen2.5",
            "mistral",
            "phi4",
            "deepseek-r1",
        ],
        _ => Vec::new(),
    }
}

/// Build a provider from its registry name.
///
/// `api_key` may be `None` for local providers such as Ollama.
pub fn create_provider(
    name: &str,
    api_key: Option<String>,
    ollama_base_url: &str,
) -> Result<Box<dyn Provider>> {
    match name {
        "openrouter" => Ok(Box::new(OpenRouterProvider::new(require_key(
            name, api_key,
        )?))),
        "openai" => Ok(Box::new(OpenAIProvider::new(require_key(name, api_key)?))),
        "anthropic" => Ok(Box::new(AnthropicProvider::new(require_key(
            name, api_key,
        )?))),
        "ollama" => Ok(Box::new(OllamaProvider::new(ollama_base_url.to_string()))),
        other => Err(EnclaveError::provider(format!(
            "unknown provider '{other}' (known: {})",
            known_providers().join(", ")
        ))),
    }
}

fn require_key(name: &str, api_key: Option<String>) -> Result<String> {
    api_key.ok_or_else(|| {
        EnclaveError::auth(format!(
            "no API key configured for '{name}'. Run: enclave keys set {name}"
        ))
    })
}

/// Scripted provider used by tests (doc-hidden, always available).
#[doc(hidden)]
pub enum MockStep {
    /// A plain text answer.
    Text(String),
    /// Tool calls plus accompanying text.
    ToolCalls(Vec<crate::core::message::ToolCall>, String),
}

#[doc(hidden)]
pub struct MockProvider {
    steps: std::sync::Mutex<std::collections::VecDeque<MockStep>>,
}

impl MockProvider {
    pub fn new(steps: Vec<MockStep>) -> Self {
        Self {
            steps: std::sync::Mutex::new(steps.into()),
        }
    }
}

#[async_trait]
impl Provider for MockProvider {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn default_model(&self) -> &'static str {
        "mock-1"
    }

    async fn chat_stream(
        &self,
        _messages: Vec<Message>,
        _model: &str,
        _effort: Option<&str>,
    ) -> Result<ChunkStream> {
        let text = match self.steps.lock().unwrap().pop_front() {
            Some(MockStep::Text(t)) => t,
            Some(MockStep::ToolCalls(_, t)) => t,
            None => String::new(),
        };
        let stream = futures::stream::iter(vec![Ok(text)]);
        Ok(Box::pin(stream))
    }

    async fn chat_with_tools(
        &self,
        _messages: Vec<Message>,
        _model: &str,
        _tools: &[ToolDef],
        _effort: Option<&str>,
    ) -> Result<ToolResponse> {
        let step = self.steps.lock().unwrap().pop_front();
        Ok(match step {
            Some(MockStep::Text(t)) => ToolResponse {
                text: t,
                tool_calls: Vec::new(),
            },
            Some(MockStep::ToolCalls(calls, text)) => ToolResponse {
                text,
                tool_calls: calls,
            },
            None => ToolResponse {
                text: String::new(),
                tool_calls: Vec::new(),
            },
        })
    }
}

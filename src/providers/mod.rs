//! Provider abstraction and registry.

use std::pin::Pin;

use async_trait::async_trait;
use futures::Stream;

use crate::core::message::Message;
use crate::error::{EnclaveError, Result};

pub mod anthropic;
pub mod ollama;
pub mod openai;
pub mod openrouter;

pub use anthropic::AnthropicProvider;
pub use ollama::OllamaProvider;
pub use openai::OpenAIProvider;
pub use openrouter::{OpenRouterModel, OpenRouterProvider};

/// A stream of text chunks produced by a provider.
pub type ChunkStream = Pin<Box<dyn Stream<Item = Result<String>> + Send>>;

/// A chat completion backend.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Stable provider name (matches the registry key).
    fn name(&self) -> &'static str;

    /// Suggested default model for this provider.
    fn default_model(&self) -> &'static str;

    /// Start a streaming chat completion.
    async fn chat_stream(&self, messages: Vec<Message>, model: &str) -> Result<ChunkStream>;

    /// Convenience: collect a full (non-streaming) completion.
    async fn chat(&self, messages: Vec<Message>, model: &str) -> Result<String> {
        use futures::StreamExt;
        let mut stream = self.chat_stream(messages, model).await?;
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

/// Build a provider from its registry name.
///
/// `api_key` may be `None` for local providers such as Ollama.
pub fn create_provider(name: &str, api_key: Option<String>, ollama_base_url: &str) -> Result<Box<dyn Provider>> {
    match name {
        "openrouter" => Ok(Box::new(OpenRouterProvider::new(require_key(name, api_key)?))),
        "openai" => Ok(Box::new(OpenAIProvider::new(require_key(name, api_key)?))),
        "anthropic" => Ok(Box::new(AnthropicProvider::new(require_key(name, api_key)?))),
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

//! Anthropic provider (Messages API).

use async_stream::try_stream;
use async_trait::async_trait;
use futures::StreamExt;

use crate::core::message::{Message, Role};
use crate::error::{EnclaveError, Result};
use crate::providers::{ChunkStream, Provider};

pub struct AnthropicProvider {
    client: reqwest::Client,
    api_key: String,
}

impl AnthropicProvider {
    pub fn new(api_key: String) -> Self {
        let _ = &api_key;
        Self {
            client: reqwest::Client::new(),
            api_key,
        }
    }
}

#[async_trait]
impl Provider for AnthropicProvider {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    fn default_model(&self) -> &'static str {
        "claude-3-5-sonnet-latest"
    }

    async fn chat_stream(&self, messages: Vec<Message>, model: &str) -> Result<ChunkStream> {
        let mut system_parts: Vec<String> = Vec::new();
        let mut wire: Vec<serde_json::Value> = Vec::new();
        for message in &messages {
            if message.role == Role::System {
                system_parts.push(message.content.clone());
            } else {
                wire.push(serde_json::to_value(message)?);
            }
        }

        let mut body = serde_json::json!({
            "model": model,
            "max_tokens": 1024,
            "stream": true,
            "messages": wire,
        });
        if !system_parts.is_empty() {
            body["system"] = serde_json::Value::String(system_parts.join("\n"));
        }

        let response = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(EnclaveError::provider(format!("anthropic {status}: {text}")));
        }

        let mut response_stream = response.bytes_stream();

        let stream = try_stream! {
            let mut buffer = String::new();
            while let Some(chunk) = response_stream.next().await {
                let bytes = chunk.map_err(EnclaveError::from)?;
                buffer.push_str(&String::from_utf8_lossy(&bytes));

                while let Some(pos) = buffer.find('\n') {
                    let line = buffer[..pos].trim_end_matches('\r').to_string();
                    buffer.drain(..=pos);

                    if let Some(data) = line.strip_prefix("data: ") {
                        let data = data.trim();
                        if let Ok(value) = serde_json::from_str::<serde_json::Value>(data) {
                            if value["type"].as_str() == Some("content_block_delta") {
                                if let Some(text) = value["delta"]["text"].as_str() {
                                    if !text.is_empty() {
                                        yield text.to_string();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };

        Ok(Box::pin(stream))
    }
}

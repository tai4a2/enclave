//! OpenAI provider (chat completions API).

use async_stream::try_stream;
use async_trait::async_trait;
use futures::StreamExt;

use crate::core::message::Message;
use crate::error::{EnclaveError, Result};
use crate::providers::{ChunkStream, Provider};

pub struct OpenAIProvider {
    client: reqwest::Client,
    api_key: String,
}

impl OpenAIProvider {
    pub fn new(api_key: String) -> Self {
        let _ = &api_key;
        Self {
            client: reqwest::Client::new(),
            api_key,
        }
    }
}

#[async_trait]
impl Provider for OpenAIProvider {
    fn name(&self) -> &'static str {
        "openai"
    }

    fn default_model(&self) -> &'static str {
        "gpt-4o-mini"
    }

    async fn chat_stream(&self, messages: Vec<Message>, model: &str) -> Result<ChunkStream> {
        let body = serde_json::json!({
            "model": model,
            "messages": serde_json::to_value(&messages)?,
            "stream": true,
        });

        let response = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(EnclaveError::provider(format!("openai {status}: {text}")));
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
                        if data == "[DONE]" {
                            return;
                        }
                        if let Ok(value) = serde_json::from_str::<serde_json::Value>(data) {
                            if let Some(text) = value["choices"][0]["delta"]["content"].as_str() {
                                if !text.is_empty() {
                                    yield text.to_string();
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

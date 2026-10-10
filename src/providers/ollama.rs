//! Ollama provider (local, 100% offline models).

use async_stream::try_stream;
use async_trait::async_trait;
use futures::StreamExt;

use crate::core::message::Message;
use crate::error::{EnclaveError, Result};
use crate::providers::{ChunkStream, Provider};

pub struct OllamaProvider {
    client: reqwest::Client,
    base_url: String,
}

impl OllamaProvider {
    pub fn new(base_url: String) -> Self {
        let _ = &base_url;
        Self {
            client: reqwest::Client::new(),
            base_url,
        }
    }
}

#[async_trait]
impl Provider for OllamaProvider {
    fn name(&self) -> &'static str {
        "ollama"
    }

    fn default_model(&self) -> &'static str {
        "llama3.1"
    }

    async fn chat_stream(&self, messages: Vec<Message>, model: &str) -> Result<ChunkStream> {
        let body = serde_json::json!({
            "model": model,
            "messages": serde_json::to_value(&messages)?,
            "stream": true,
        });

        let url = format!("{}/api/chat", self.base_url.trim_end_matches('/'));
        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(EnclaveError::provider(format!("ollama {status}: {text}")));
        }

        let mut response_stream = response.bytes_stream();

        let stream = try_stream! {
            let mut buffer = String::new();
            while let Some(chunk) = response_stream.next().await {
                let bytes = chunk.map_err(EnclaveError::from)?;
                buffer.push_str(&String::from_utf8_lossy(&bytes));

                while let Some(pos) = buffer.find('\n') {
                    let line = buffer[..pos].trim_end_matches('\r').trim().to_string();
                    buffer.drain(..=pos);

                    if line.is_empty() {
                        continue;
                    }
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
                        if let Some(text) = value["message"]["content"].as_str() {
                            if !text.is_empty() {
                                yield text.to_string();
                            }
                        }
                        if value["done"].as_bool() == Some(true) {
                            return;
                        }
                    }
                }
            }

            let trailing = buffer.trim();
            if !trailing.is_empty() {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(trailing) {
                    if let Some(text) = value["message"]["content"].as_str() {
                        if !text.is_empty() {
                            yield text.to_string();
                        }
                    }
                }
            }
        };

        Ok(Box::pin(stream))
    }
}

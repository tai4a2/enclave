//! OpenRouter provider (multi-model gateway, OpenAI-compatible API).

use async_stream::try_stream;
use async_trait::async_trait;
use futures::StreamExt;

use crate::core::message::Message;
use crate::error::{EnclaveError, Result};
use crate::providers::{ChunkStream, Provider};

pub struct OpenRouterProvider {
    client: reqwest::Client,
    api_key: String,
}

impl OpenRouterProvider {
    pub fn new(api_key: String) -> Self {
        let _ = &api_key;
        Self {
            client: reqwest::Client::new(),
            api_key,
        }
    }
}

/// One entry of the public OpenRouter model catalogue.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenRouterModel {
    pub id: String,
    pub name: String,
    pub context_length: u64,
    /// USD per 1M prompt tokens.
    pub prompt_price: f64,
    /// USD per 1M completion tokens.
    pub completion_price: f64,
}

impl OpenRouterModel {
    pub fn is_free(&self) -> bool {
        self.prompt_price == 0.0 && self.completion_price == 0.0
    }

    pub async fn fetch_all() -> Result<Vec<OpenRouterModel>> {
        let client = reqwest::Client::new();
        let value: serde_json::Value = client
            .get("https://openrouter.ai/api/v1/models")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(parse_models(&value))
    }
}

/// Parse the public catalogue response (no API key needed).
pub fn parse_models(value: &serde_json::Value) -> Vec<OpenRouterModel> {
    let mut models = Vec::new();
    let Some(entries) = value["data"].as_array() else {
        return models;
    };
    for e in entries {
        let Some(id) = e["id"].as_str() else {
            continue;
        };
        let price_str = |field: &str| -> f64 {
            e["pricing"][field].as_str().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0)
        };
        models.push(OpenRouterModel {
            id: id.to_string(),
            name: e["name"].as_str().unwrap_or_default().to_string(),
            context_length: e["context_length"].as_u64().unwrap_or(0),
            prompt_price: price_str("prompt") * 1_000_000.0,
            completion_price: price_str("completion") * 1_000_000.0,
        });
    }
    models.sort_by(|a, b| a.id.cmp(&b.id));
    models
}

#[async_trait]
impl Provider for OpenRouterProvider {
    fn name(&self) -> &'static str {
        "openrouter"
    }

    fn default_model(&self) -> &'static str {
        "mistralai/mistral-large-4-0"
    }

    async fn chat_stream(&self, messages: Vec<Message>, model: &str) -> Result<ChunkStream> {
        let body = serde_json::json!({
            "model": model,
            "messages": serde_json::to_value(&messages)?,
            "stream": true,
        });

        let response = self
            .client
            .post("https://openrouter.ai/api/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .header("HTTP-Referer", "https://github.com/enclave")
            .header("X-Title", "Enclave CLI")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(EnclaveError::provider(format!("openrouter {status}: {text}")));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_models_extracts_fields_and_sorts() {
        let json = serde_json::json!({
            "data": [
                {
                    "id": "zeta/model",
                    "name": "Zeta Model",
                    "context_length": 8192,
                    "pricing": {"prompt": "0.000001", "completion": "0.000002"}
                },
                {
                    "id": "alpha/free",
                    "name": "Alpha Free",
                    "context_length": 4096,
                    "pricing": {"prompt": "0", "completion": "0"}
                }
            ]
        });
        let mut models = parse_models(&json);
        models.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].id, "alpha/free");
        assert!(models[0].is_free());
        assert_eq!(models[1].prompt_price, 1.0); // per 1M tokens
        assert_eq!(models[1].completion_price, 2.0);
        assert!(!models[1].is_free());
        assert_eq!(models[1].context_length, 8192);
    }

    #[test]
    fn parse_models_tolerates_malformed_entries() {
        let json = serde_json::json!({
            "data": [
                {"id": "ok/model", "name": "Ok", "pricing": {"prompt": "0", "completion": "0"}},
                {"no_id": true},
                {"id": "missing/pricing"}
            ]
        });
        let models = parse_models(&json);
        assert_eq!(models.len(), 2);
        // Missing pricing degrades to 0 (free-flagged) rather than panicking.
        assert!(models.iter().any(|m| m.id == "missing/pricing" && m.is_free()));
    }
}

//! OpenRouter provider (multi-model gateway, OpenAI-compatible API).

use async_stream::try_stream;
use async_trait::async_trait;
use futures::StreamExt;

use crate::core::message::Message;
use crate::error::{EnclaveError, Result};
use crate::providers::openai_compat;
use crate::providers::{ChunkStream, Provider, ToolDef, ToolResponse};

pub struct OpenRouterProvider {
    client: reqwest::Client,
    api_key: String,
}

impl OpenRouterProvider {
    pub fn new(api_key: String) -> Self {
        let _ = &api_key;
        Self {
            client: crate::providers::http::client(),
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
        let client = crate::providers::http::client();
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

/// Account/credit information for the configured OpenRouter key.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OpenRouterAccount {
    pub label: Option<String>,
    /// Total credits ever purchased (account level).
    pub total_credits: Option<f64>,
    /// Total credits consumed (account level).
    pub total_usage: Option<f64>,
    /// Credit limit on the API key, if any.
    pub key_limit: Option<f64>,
    /// Usage charged to the API key.
    pub key_usage: Option<f64>,
    pub is_free_tier: Option<bool>,
    /// e.g. "20 req/10s".
    pub rate_limit: Option<String>,
}

impl OpenRouterAccount {
    /// Fetch the account info for `api_key`.
    pub async fn fetch(api_key: &str) -> Result<Self> {
        fetch_account(api_key).await
    }

    pub fn total_remaining(&self) -> Option<f64> {
        Some(self.total_credits? - self.total_usage?)
    }

    pub fn key_remaining(&self) -> Option<f64> {
        Some(self.key_limit? - self.key_usage?)
    }

    /// Compact one-line summary for the header/footer.
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        match (self.total_usage, self.total_credits) {
            (Some(u), Some(c)) => parts.push(format!("${u:.2}/${c:.2} used")),
            (Some(u), None) => parts.push(format!("${u:.2} used")),
            _ => {}
        }
        if let Some(r) = self.total_remaining() {
            parts.push(format!("${r:.2} left"));
        }
        if let Some(k) = self.key_remaining() {
            parts.push(format!("key ${k:.2} left"));
        } else if let Some(l) = self.key_limit {
            parts.push(format!("key limit ${l:.2}"));
        }
        if self.is_free_tier == Some(true) {
            parts.push("free tier".into());
        }
        if let Some(rl) = &self.rate_limit {
            parts.push(rl.clone());
        }
        if parts.is_empty() {
            "no account data".into()
        } else {
            parts.join(" · ")
        }
    }

    /// Multi-line report for the `/credits` transcript entry.
    pub fn report(&self) -> String {
        let mut lines = vec!["OpenRouter account".to_string()];
        if let Some(l) = &self.label {
            lines.push(format!("  key label     : {l}"));
        }
        match (self.total_usage, self.total_credits) {
            (Some(u), Some(c)) => {
                lines.push(format!("  credits used  : ${u:.2} of ${c:.2}"));
                lines.push(format!("  credits left  : ${:.2}", c - u));
            }
            (Some(u), None) => lines.push(format!("  credits used  : ${u:.2}")),
            _ => {}
        }
        match (self.key_usage, self.key_limit) {
            (Some(u), Some(l)) => {
                lines.push(format!("  key used      : ${u:.2} of ${l:.2} (limit)"));
                lines.push(format!("  key remaining : ${:.2}", l - u));
            }
            (Some(u), None) => lines.push(format!("  key used      : ${u:.2} (no key limit)")),
            _ => {}
        }
        if let Some(f) = self.is_free_tier {
            lines.push(format!("  free tier     : {f}"));
        }
        if let Some(rl) = &self.rate_limit {
            lines.push(format!("  rate limit    : {rl}"));
        }
        lines.join("\n")
    }
}

/// Fetch account/credit info for `api_key` (best-effort: missing endpoints
/// degrade to empty fields rather than failing).
pub async fn fetch_account(api_key: &str) -> Result<OpenRouterAccount> {
    let client = crate::providers::http::client();
    let html_headers = |req: reqwest::RequestBuilder| {
        req.header("Authorization", format!("Bearer {api_key}"))
            .header("HTTP-Referer", "https://github.com/enclave")
            .header("X-Title", "Enclave CLI")
    };

    let credits: Option<serde_json::Value> = async {
        let r = html_headers(client.get("https://openrouter.ai/api/v1/credits"))
            .send()
            .await
            .ok()?;
        if !r.status().is_success() {
            return None;
        }
        r.json().await.ok()
    }
    .await;

    let key: Option<serde_json::Value> = async {
        let r = html_headers(client.get("https://openrouter.ai/api/v1/auth/key"))
            .send()
            .await
            .ok()?;
        if !r.status().is_success() {
            return None;
        }
        r.json().await.ok()
    }
    .await;

    Ok(parse_account(credits.as_ref(), key.as_ref()))
}

/// Parse the `/credits` and `/auth/key` responses (both optional).
pub fn parse_account(
    credits: Option<&serde_json::Value>,
    key: Option<&serde_json::Value>,
) -> OpenRouterAccount {
    let mut acc = OpenRouterAccount::default();
    if let Some(c) = credits {
        acc.total_credits = c["data"]["total_credits"].as_f64();
        acc.total_usage = c["data"]["total_usage"].as_f64();
    }
    if let Some(k) = key {
        let d = &k["data"];
        acc.label = d["label"].as_str().map(str::to_string);
        acc.key_usage = d["usage"].as_f64();
        acc.key_limit = d["limit"].as_f64();
        acc.is_free_tier = d["is_free_tier"].as_bool();
        let rl = &d["rate_limit"];
        if let (Some(r), Some(i)) = (rl["requests"].as_f64(), rl["interval"].as_str()) {
            acc.rate_limit = Some(format!("{r:.0} req/{i}"));
        }
    }
    acc
}

#[async_trait]
impl Provider for OpenRouterProvider {
    fn name(&self) -> &'static str {
        "openrouter"
    }

    fn default_model(&self) -> &'static str {
        "mistralai/mistral-large-4-0"
    }

    async fn chat_stream(
        &self,
        messages: Vec<Message>,
        model: &str,
        effort: Option<&str>,
    ) -> Result<ChunkStream> {
        let mut body = serde_json::json!({
            "model": model,
            "messages": serde_json::to_value(&messages)?,
            "stream": true,
        });
        if let Some(e) = effort {
            body["reasoning_effort"] = serde_json::json!(e);
        }

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

                    if let Some(data) = line.strip_prefix("data:").map(str::trim) {
                        let data = data.trim();
                        if data == "[DONE]" {
                            return;
                        }
                        if let Ok(value) = serde_json::from_str::<serde_json::Value>(data) {
                            if let Some(msg) = value["error"]["message"].as_str() {
                                Err(EnclaveError::provider(format!(
                                    "openrouter stream error: {msg}"
                                )))?;
                            }
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

    async fn chat_with_tools(
        &self,
        messages: Vec<Message>,
        model: &str,
        tools: &[ToolDef],
        effort: Option<&str>,
    ) -> Result<ToolResponse> {
        let mut body = serde_json::json!({
            "model": model,
            "messages": openai_compat::wire_messages(&messages),
            "stream": false,
            "tools": openai_compat::tools_json(tools),
            "tool_choice": "auto",
        });
        if let Some(e) = effort {
            body["reasoning_effort"] = serde_json::json!(e);
        }

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

        let value: serde_json::Value = response.json().await?;
        let (text, tool_calls) = openai_compat::parse_response(&value);
        Ok(ToolResponse { text, tool_calls })
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

    #[test]
    fn parse_account_reads_credits_and_key() {
        let credits = serde_json::json!({
            "data": {"total_credits": 10.0, "total_usage": 2.5}
        });
        let key = serde_json::json!({
            "data": {
                "label": "sk-test",
                "usage": 2.5,
                "limit": 10.0,
                "is_free_tier": false,
                "rate_limit": {"requests": 20, "interval": "10s"}
            }
        });
        let acc = parse_account(Some(&credits), Some(&key));
        assert_eq!(acc.total_remaining(), Some(7.5));
        assert_eq!(acc.key_remaining(), Some(7.5));
        assert_eq!(acc.rate_limit.as_deref(), Some("20 req/10s"));
        assert!(acc.summary().contains("$2.50/$10.00 used"));
        assert!(acc.summary().contains("$7.50 left"));
        assert!(acc.report().contains("credits left  : $7.50"));
    }

    #[test]
    fn parse_account_tolerates_missing_data() {
        let acc = parse_account(None, None);
        assert_eq!(acc.total_remaining(), None);
        assert_eq!(acc.key_remaining(), None);
        assert_eq!(acc.summary(), "no account data");
        let key_only = serde_json::json!({"data": {"usage": 1.0, "is_free_tier": true}});
        let acc = parse_account(None, Some(&key_only));
        assert_eq!(acc.key_remaining(), None);
        assert!(acc.summary().contains("free tier"));
    }
}

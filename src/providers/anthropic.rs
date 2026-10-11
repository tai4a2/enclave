//! Anthropic provider (Messages API).

use async_stream::try_stream;
use async_trait::async_trait;
use futures::StreamExt;

use crate::core::message::{Message, Role, ToolCall};
use crate::error::{EnclaveError, Result};
use crate::providers::{ChunkStream, Provider, ToolDef, ToolResponse};

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

/// Build Anthropic wire messages: tool results are grouped into a single
/// `user` message of `tool_result` blocks (as the API requires).
pub fn wire_messages(messages: &[Message]) -> Vec<serde_json::Value> {
    let mut wire: Vec<serde_json::Value> = Vec::new();
    let mut i = 0;
    while i < messages.len() {
        let m = &messages[i];
        match m.role {
            Role::System => {
                i += 1;
            }
            Role::Tool => {
                // Group consecutive tool results into one user message.
                let mut blocks = Vec::new();
                while i < messages.len() && messages[i].role == Role::Tool {
                    let t = &messages[i];
                    blocks.push(serde_json::json!({
                        "type": "tool_result",
                        "tool_use_id": t.tool_call_id.clone().unwrap_or_default(),
                        "content": t.content,
                    }));
                    i += 1;
                }
                wire.push(serde_json::json!({ "role": "user", "content": blocks }));
            }
            Role::User => {
                if m.attachments.is_empty() {
                    wire.push(serde_json::json!({ "role": "user", "content": m.content }));
                } else {
                    let mut blocks = Vec::new();
                    let mut text = m.content.clone();
                    for a in &m.attachments {
                        if let Some(body) = a.text_body() {
                            if !text.is_empty() {
                                text.push_str("\n\n");
                            }
                            text.push_str(&format!("[{}]\n{}", a.name, body));
                        }
                    }
                    if !text.is_empty() {
                        blocks.push(serde_json::json!({ "type": "text", "text": text }));
                    }
                    for a in &m.attachments {
                        if a.is_image() {
                            blocks.push(serde_json::json!({
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": a.mime,
                                    "data": a.data,
                                },
                            }));
                        }
                    }
                    wire.push(serde_json::json!({ "role": "user", "content": blocks }));
                }
                i += 1;
            }
            Role::Assistant => {
                let mut blocks = Vec::new();
                if !m.content.is_empty() {
                    blocks.push(serde_json::json!({ "type": "text", "text": m.content }));
                }
                for c in &m.tool_calls {
                    let input = serde_json::from_str::<serde_json::Value>(&c.arguments)
                        .unwrap_or_else(|_| serde_json::json!({}));
                    blocks.push(serde_json::json!({
                        "type": "tool_use",
                        "id": c.id,
                        "name": c.name,
                        "input": input,
                    }));
                }
                wire.push(serde_json::json!({ "role": "assistant", "content": blocks }));
                i += 1;
            }
        }
    }
    wire
}

/// Parse an Anthropic non-streaming response into text + tool calls.
pub fn parse_response(value: &serde_json::Value) -> (String, Vec<ToolCall>) {
    let mut text = String::new();
    let mut calls = Vec::new();
    if let Some(blocks) = value["content"].as_array() {
        for b in blocks {
            match b["type"].as_str() {
                Some("text") => {
                    if let Some(t) = b["text"].as_str() {
                        text.push_str(t);
                    }
                }
                Some("tool_use") => {
                    let arguments = serde_json::to_string(&b["input"])
                        .unwrap_or_else(|_| "{}".into());
                    calls.push(ToolCall {
                        id: b["id"].as_str().unwrap_or_default().to_string(),
                        name: b["name"].as_str().unwrap_or_default().to_string(),
                        arguments,
                    });
                }
                _ => {}
            }
        }
    }
    (text, calls)
}

#[async_trait]
impl Provider for AnthropicProvider {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    fn default_model(&self) -> &'static str {
        "claude-3-5-sonnet-latest"
    }

    async fn chat_stream(
        &self,
        messages: Vec<Message>,
        model: &str,
        _effort: Option<&str>,
    ) -> Result<ChunkStream> {
        let system_parts: Vec<String> = messages
            .iter()
            .filter(|m| m.role == Role::System)
            .map(|m| m.content.clone())
            .collect();
        let wire = wire_messages(&messages);

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

    async fn chat_with_tools(
        &self,
        messages: Vec<Message>,
        model: &str,
        tools: &[ToolDef],
        _effort: Option<&str>,
    ) -> Result<ToolResponse> {
        let mut system_parts: Vec<String> = Vec::new();
        for message in &messages {
            if message.role == Role::System {
                system_parts.push(message.content.clone());
            }
        }

        let mut body = serde_json::json!({
            "model": model,
            "max_tokens": 4096,
            "stream": false,
            "messages": wire_messages(&messages),
            "tools": tools.iter().map(|t| serde_json::json!({
                "name": t.name,
                "description": t.description,
                "input_schema": t.parameters,
            })).collect::<Vec<_>>(),
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

        let value: serde_json::Value = response.json().await?;
        let (text, tool_calls) = parse_response(&value);
        Ok(ToolResponse { text, tool_calls })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_groups_tool_results_and_shapes_tool_use() {
        let calls = vec![ToolCall {
            id: "tu_1".into(),
            name: "read_file".into(),
            arguments: r#"{"path":"f"}"#.into(),
        }];
        let msgs = vec![
            Message::system("be nice"),
            Message::user("hi"),
            Message::assistant_with_tool_calls(String::new(), calls),
            Message::tool_result("tu_1", "data"),
        ];
        let wire = wire_messages(&msgs);
        assert_eq!(wire.len(), 3);
        assert_eq!(wire[0]["role"], "user");
        assert_eq!(wire[1]["content"][0]["type"], "tool_use");
        assert_eq!(wire[1]["content"][0]["input"]["path"], "f");
        assert_eq!(wire[2]["content"][0]["type"], "tool_result");
        assert_eq!(wire[2]["content"][0]["tool_use_id"], "tu_1");
    }

    #[test]
    fn wire_user_with_image_uses_content_blocks() {
        use crate::core::attachment::{Attachment, AttachmentKind};
        let img = Attachment {
            kind: AttachmentKind::Image,
            name: "a.png".into(),
            mime: "image/png".into(),
            data: "QUJD".into(),
        };
        let wire = wire_messages(&[Message::user_with_attachments("what is this?", vec![img])]);
        let blocks = wire[0]["content"].as_array().unwrap();
        assert_eq!(blocks[0]["type"], "text");
        assert_eq!(blocks[0]["text"], "what is this?");
        assert_eq!(blocks[1]["type"], "image");
        assert_eq!(blocks[1]["source"]["type"], "base64");
        assert_eq!(blocks[1]["source"]["media_type"], "image/png");
        assert_eq!(blocks[1]["source"]["data"], "QUJD");
    }

    #[test]
    fn parse_reads_text_and_tool_use_blocks() {
        let value = serde_json::json!({
            "content": [
                {"type": "text", "text": "checking"},
                {"type": "tool_use", "id": "tu_2", "name": "list_dir", "input": {"path": "."}}
            ]
        });
        let (text, calls) = parse_response(&value);
        assert_eq!(text, "checking");
        assert_eq!(calls[0].name, "list_dir");
        assert_eq!(calls[0].id, "tu_2");
        assert!(calls[0].arguments.contains("\"path\""));
    }
}

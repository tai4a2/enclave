//! Shared helpers for OpenAI-compatible chat-completions APIs
//! (OpenRouter, OpenAI, and Ollama's native chat use near-identical shapes).

use serde_json::{Value, json};

use crate::core::message::{Message, Role, ToolCall};
use crate::providers::ToolDef;

/// Convert history messages to the OpenAI-compatible wire format,
/// including assistant `tool_calls` and `role: "tool"` results.
pub fn wire_messages(messages: &[Message]) -> Vec<Value> {
    messages
        .iter()
        .map(|m| match m.role {
            Role::Tool => json!({
                "role": "tool",
                "tool_call_id": m.tool_call_id.clone().unwrap_or_default(),
                "content": m.content,
            }),
            _ => {
                let mut v = json!({ "role": m.role.as_str(), "content": m.content });
                if !m.tool_calls.is_empty() {
                    v["tool_calls"] = Value::Array(
                        m.tool_calls
                            .iter()
                            .map(|c| {
                                json!({
                                    "id": c.id,
                                    "type": "function",
                                    "function": { "name": c.name, "arguments": c.arguments },
                                })
                            })
                            .collect(),
                    );
                }
                v
            }
        })
        .collect()
}

/// Ollama variant: `tool_calls[].function.arguments` is an object, not a string.
pub fn ollama_wire_messages(messages: &[Message]) -> Vec<Value> {
    messages
        .iter()
        .map(|m| {
            let mut v = json!({ "role": m.role.as_str(), "content": m.content });
            if m.role == Role::Tool {
                v["tool_call_id"] = json!(m.tool_call_id.clone().unwrap_or_default());
            }
            if !m.tool_calls.is_empty() {
                v["tool_calls"] = Value::Array(
                    m.tool_calls
                        .iter()
                        .map(|c| {
                            let args = serde_json::from_str::<Value>(&c.arguments)
                                .unwrap_or_else(|_| json!({}));
                            json!({ "function": { "name": c.name, "arguments": args } })
                        })
                        .collect(),
                );
            }
            v
        })
        .collect()
}

/// Tool definitions in the OpenAI/Ollama wire format.
pub fn tools_json(tools: &[ToolDef]) -> Value {
    Value::Array(
        tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    },
                })
            })
            .collect(),
    )
}

/// Extract `{text, tool_calls}` from a non-streaming OpenAI-compatible response.
pub fn parse_response(value: &Value) -> (String, Vec<ToolCall>) {
    let message = &value["choices"][0]["message"];
    let text = message["content"].as_str().unwrap_or_default().to_string();
    let mut calls = Vec::new();
    if let Some(array) = message["tool_calls"].as_array() {
        for (i, c) in array.iter().enumerate() {
            let name = c["function"]["name"].as_str().unwrap_or_default().to_string();
            if name.is_empty() {
                continue;
            }
            calls.push(ToolCall {
                id: c["id"]
                    .as_str()
                    .unwrap_or(&format!("call_{i}"))
                    .to_string(),
                name,
                arguments: c["function"]["arguments"]
                    .as_str()
                    .unwrap_or("{}")
                    .to_string(),
            });
        }
    }
    (text, calls)
}

/// Extract `{text, tool_calls}` from an Ollama native `/api/chat` response.
pub fn parse_ollama_response(value: &Value) -> (String, Vec<ToolCall>) {
    let message = &value["message"];
    let text = message["content"].as_str().unwrap_or_default().to_string();
    let mut calls = Vec::new();
    if let Some(array) = message["tool_calls"].as_array() {
        for (i, c) in array.iter().enumerate() {
            let name = c["function"]["name"].as_str().unwrap_or_default().to_string();
            if name.is_empty() {
                continue;
            }
            let args = &c["function"]["arguments"];
            let arguments = match args {
                Value::String(s) => s.clone(),
                other => serde_json::to_string(other).unwrap_or_else(|_| "{}".into()),
            };
            calls.push(ToolCall {
                id: format!("call_{i}"),
                name,
                arguments,
            });
        }
    }
    (text, calls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::message::Message;

    #[test]
    fn wire_messages_shapes_tool_traffic() {
        let calls = vec![ToolCall {
            id: "abc".into(),
            name: "read_file".into(),
            arguments: r#"{"path":"a.txt"}"#.into(),
        }];
        let msgs = vec![
            Message::user("hi"),
            Message::assistant_with_tool_calls(String::new(), calls),
            Message::tool_result("abc", "contents"),
        ];
        let wire = wire_messages(&msgs);
        assert_eq!(wire[0]["role"], "user");
        assert_eq!(wire[1]["tool_calls"][0]["function"]["name"], "read_file");
        assert_eq!(wire[1]["tool_calls"][0]["id"], "abc");
        assert_eq!(wire[2]["role"], "tool");
        assert_eq!(wire[2]["tool_call_id"], "abc");
    }

    #[test]
    fn ollama_wire_uses_object_arguments() {
        let calls = vec![ToolCall {
            id: "call_0".into(),
            name: "list_dir".into(),
            arguments: r#"{"path":"."}"#.into(),
        }];
        let msgs = vec![Message::assistant_with_tool_calls(String::new(), calls)];
        let wire = ollama_wire_messages(&msgs);
        assert_eq!(wire[0]["tool_calls"][0]["function"]["arguments"]["path"], ".");
    }

    #[test]
    fn parse_response_reads_tool_calls() {
        let value = json!({
            "choices": [{
                "message": {
                    "content": "working",
                    "tool_calls": [
                        {"id": "t1", "function": {"name": "run_shell", "arguments": "{\"command\":\"ls\"}"}}
                    ]
                }
            }]
        });
        let (text, calls) = parse_response(&value);
        assert_eq!(text, "working");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "run_shell");
        assert_eq!(calls[0].id, "t1");
    }

    #[test]
    fn parse_ollama_response_object_arguments() {
        let value = json!({
            "message": {
                "content": "",
                "tool_calls": [
                    {"function": {"name": "read_file", "arguments": {"path": "x"}}}
                ]
            }
        });
        let (_, calls) = parse_ollama_response(&value);
        assert_eq!(calls[0].id, "call_0");
        assert!(calls[0].arguments.contains(r#""path":"x""#) || calls[0].arguments.contains(r#""path": "x""#));
    }
}
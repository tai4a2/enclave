//! The message model used across providers and storage.

use serde::{Deserialize, Serialize};

use crate::core::attachment::Attachment;

/// Role of a chat message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

impl Role {
    /// Wire/DB representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
        }
    }

    /// Parse a role, defaulting to [`Role::User`] for unknown values.
    pub fn parse(s: &str) -> Role {
        match s {
            "system" => Role::System,
            "assistant" => Role::Assistant,
            "tool" => Role::Tool,
            _ => Role::User,
        }
    }
}

/// One function/tool invocation requested by the assistant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    /// Stable id assigned by the provider (echoed in the tool result).
    #[serde(default)]
    pub id: String,
    /// Tool name.
    pub name: String,
    /// JSON-encoded arguments object.
    pub arguments: String,
}

/// A single chat message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: String,
    /// Tool calls requested by an assistant message.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    /// For `Role::Tool` messages: the id of the call this result answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Files attached to this message (images or text).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
}

impl Message {
    pub fn new(role: Role, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: None,
            attachments: Vec::new(),
        }
    }

    pub fn system(content: impl Into<String>) -> Self {
        Self::new(Role::System, content)
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self::new(Role::User, content)
    }

    /// A user message carrying file attachments.
    pub fn user_with_attachments(content: impl Into<String>, attachments: Vec<Attachment>) -> Self {
        let mut m = Self::new(Role::User, content);
        m.attachments = attachments;
        m
    }

    /// Attach files to any message (builder style).
    pub fn with_attachments(mut self, attachments: Vec<Attachment>) -> Self {
        self.attachments = attachments;
        self
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self::new(Role::Assistant, content)
    }

    /// Assistant message carrying tool calls (content may be empty).
    pub fn assistant_with_tool_calls(content: impl Into<String>, calls: Vec<ToolCall>) -> Self {
        let mut m = Self::new(Role::Assistant, content);
        m.tool_calls = calls;
        m
    }

    /// Tool result answering `tool_call_id`.
    pub fn tool_result(call_id: impl Into<String>, content: impl Into<String>) -> Self {
        let mut m = Self::new(Role::Tool, content);
        m.tool_call_id = Some(call_id.into());
        m
    }
}
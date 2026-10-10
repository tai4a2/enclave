//! The chat engine: ties a provider, the encrypted memory and a session together.

use crate::core::message::Message;
use crate::core::session::Session;
use crate::error::Result;
use crate::privacy::memory::EncryptedMemory;
use crate::providers::{ChunkStream, Provider};

/// Orchestrates a conversation turn by turn.
pub struct ChatEngine {
    pub provider: Box<dyn Provider>,
    pub model: String,
    pub memory: EncryptedMemory,
    pub session: Session,
    pub system_prompt: Option<String>,
}

impl ChatEngine {
    pub fn new(
        provider: Box<dyn Provider>,
        model: String,
        memory: EncryptedMemory,
        session: Session,
        system_prompt: Option<String>,
    ) -> Self {
        ChatEngine {
            provider,
            model,
            memory,
            session,
            system_prompt,
        }
    }

    /// Provider name.
    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
    }

    /// Build the message list sent to the provider (system prompt + history).
    pub fn request_messages(&self) -> Vec<Message> {
        let mut msgs: Vec<Message> = Vec::new();
        if let Some(sp) = &self.system_prompt {
            msgs.push(Message::system(sp.clone()));
        }
        msgs.extend(self.session.messages.iter().cloned());
        msgs
    }

    /// Persist the user's input and start streaming the assistant reply.
    pub async fn stream_reply(&mut self, input: &str) -> Result<ChunkStream> {
        self.session.add_user(&self.memory, input)?;
        let messages = self.request_messages();
        self.provider.chat_stream(messages, &self.model).await
    }

    /// Persist a completed assistant reply.
    pub fn commit_assistant(&mut self, content: String) -> Result<()> {
        self.session.add_assistant(&self.memory, &content)
    }
}

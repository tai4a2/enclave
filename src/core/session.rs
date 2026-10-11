//! Session abstraction: an in-memory view of a stored conversation.

use crate::core::message::Message;
use crate::error::{EnclaveError, Result};
use crate::privacy::memory::EncryptedMemory;

/// An active chat session.
pub struct Session {
    pub id: String,
    pub name: String,
    pub messages: Vec<Message>,
    /// Ephemeral sessions never touch the encrypted store (sub-agents).
    pub ephemeral: bool,
}

impl Session {
    /// Build a session from already-loaded messages.
    pub fn from_messages(id: String, name: String, messages: Vec<Message>) -> Self {
        Session {
            id,
            name,
            messages,
            ephemeral: false,
        }
    }

    /// A RAM-only session for sub-agents: nothing is persisted.
    pub fn ephemeral(name: &str) -> Self {
        Session {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            messages: Vec::new(),
            ephemeral: true,
        }
    }

    /// Create a brand new session and persist it.
    pub fn create(memory: &EncryptedMemory, name: &str) -> Result<Self> {
        let id = memory.create_session(name)?;
        Ok(Session {
            id,
            name: name.to_string(),
            messages: Vec::new(),
            ephemeral: false,
        })
    }

    /// Load an existing session and its history.
    pub fn load(memory: &EncryptedMemory, id: &str) -> Result<Self> {
        if !memory.session_exists(id)? {
            return Err(EnclaveError::other(format!("session '{id}' not found")));
        }
        let name = memory
            .list_sessions()?
            .into_iter()
            .find(|s| s.id == id)
            .map(|s| s.name)
            .unwrap_or_else(|| id.to_string());
        let messages = memory.get_history(id, 100_000)?;
        Ok(Session {
            id: id.to_string(),
            name,
            messages,
            ephemeral: false,
        })
    }

    /// Append a user message (RAM + encrypted store).
    pub fn add_user(&mut self, memory: &EncryptedMemory, content: &str) -> Result<()> {
        self.push(Message::user(content), memory)
    }

    /// Append an assistant message (RAM + encrypted store).
    pub fn add_assistant(&mut self, memory: &EncryptedMemory, content: &str) -> Result<()> {
        self.push(Message::assistant(content), memory)
    }

    /// Append any message (including tool calls/results), persisting metadata.
    pub fn push(&mut self, message: Message, memory: &EncryptedMemory) -> Result<()> {
        if !self.ephemeral {
            memory.save_message_full(&self.id, &message)?;
        }
        self.messages.push(message);
        Ok(())
    }

    /// Clear the conversation (RAM + encrypted store).
    pub fn clear(&mut self, memory: &EncryptedMemory) -> Result<()> {
        memory.delete_session(&self.id)?;
        self.id = memory.create_session(&self.name)?;
        self.messages.clear();
        Ok(())
    }
}
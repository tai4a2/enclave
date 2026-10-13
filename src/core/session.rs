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

    /// Fork another session into a fresh branch (Conversation Git): a new session
    /// is created copying the first `keep` messages of `parent_id` (clamped to the
    /// parent's length), and its branch lineage is recorded.
    pub fn fork(
        memory: &EncryptedMemory,
        parent_id: &str,
        name: &str,
        keep: usize,
    ) -> Result<Self> {
        let history = memory.get_history(parent_id, 100_000)?;
        let take = keep.min(history.len());
        let id = memory.create_session(name)?;
        let mut messages = Vec::new();
        for message in history.into_iter().take(take) {
            memory.save_message_full(&id, &message)?;
            messages.push(message);
        }
        memory.set_branch(&id, parent_id, take)?;
        Ok(Session {
            id,
            name: name.to_string(),
            messages,
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

    /// Drop all messages after the first `keep` (RAM + encrypted store).
    /// Used by undo/retry.
    pub fn truncate_to(&mut self, memory: &EncryptedMemory, keep: usize) -> Result<()> {
        if keep >= self.messages.len() {
            return Ok(());
        }
        let remove = self.messages.len() - keep;
        memory.delete_last_messages(&self.id, remove)?;
        self.messages.truncate(keep);
        Ok(())
    }

    /// Replace the whole conversation with a single system summary (compaction).
    pub fn compact_with(&mut self, memory: &EncryptedMemory, summary: &str) -> Result<()> {
        memory.clear_session_messages(&self.id)?;
        self.messages.clear();
        let message = Message::system(format!(
            "Conversation summary so far (earlier turns were compacted):\n\n{summary}"
        ));
        self.push(message, memory)
    }
}
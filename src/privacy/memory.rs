//! Encrypted chat memory backed by SQLCipher (AES-256).
//!
//! This is the "vault": every message is stored encrypted at rest and is
//! unreadable without the master key.

use std::path::Path;

use serde::{Deserialize, Serialize};

use rusqlite::OptionalExtension;

use crate::core::attachment::Attachment;
use crate::core::message::{Message, Role, ToolCall};
use crate::error::{EnclaveError, Result};
use crate::privacy::vault::MasterKey;

/// Tool-call metadata persisted alongside a message.
#[derive(Debug, Default, Serialize, Deserialize)]
struct MessageMeta {
    #[serde(default)]
    tool_calls: Vec<ToolCall>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    attachments: Vec<Attachment>,
}

fn encode_meta(message: &Message) -> Result<String> {
    if message.tool_calls.is_empty()
        && message.tool_call_id.is_none()
        && message.attachments.is_empty()
    {
        return Ok(String::new());
    }
    let meta = MessageMeta {
        tool_calls: message.tool_calls.clone(),
        tool_call_id: message.tool_call_id.clone(),
        attachments: message.attachments.clone(),
    };
    serde_json::to_string(&meta).map_err(EnclaveError::from)
}

fn decode_meta(role: Role, content: String, meta: &str) -> Message {
    let mut message = Message::new(role, content);
    if !meta.is_empty() {
        if let Ok(parsed) = serde_json::from_str::<MessageMeta>(meta) {
            message.tool_calls = parsed.tool_calls;
            message.tool_call_id = parsed.tool_call_id;
            message.attachments = parsed.attachments;
        }
    }
    message
}

fn snippet_for(content: &str, query: &str) -> String {
    let needle = query.to_lowercase();
    for line in content.lines() {
        if line.to_lowercase().contains(&needle) {
            let trimmed = line.trim();
            let mut s: String = trimmed.chars().take(100).collect();
            if trimmed.chars().count() > 100 {
                s.push('…');
            }
            return s;
        }
    }
    let mut s: String = content.trim().chars().take(100).collect();
    if content.trim().chars().count() > 100 {
        s.push('…');
    }
    s
}

/// Escape `%` and `_` so a user query is matched literally in a LIKE clause.
fn escape_like(query: &str) -> String {
    query
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Map a `memories` row (columns: id, text, tags, kind, source_session, pinned,
/// local_only, created_at, updated_at) into a [`Memory`].
fn map_memory(row: &rusqlite::Row<'_>) -> rusqlite::Result<Memory> {
    Ok(Memory {
        id: row.get(0)?,
        text: row.get(1)?,
        tags: row.get(2)?,
        kind: row.get(3)?,
        source_session: row.get(4)?,
        pinned: row.get::<_, i64>(5)? != 0,
        local_only: row.get::<_, i64>(6)? != 0,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

/// Summary row describing a stored session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: String,
    pub name: String,
    pub updated_at: String,
    pub message_count: i64,
}

/// Database statistics (all counts refer to decrypted content).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbStats {
    pub page_size: i64,
    pub page_count: i64,
    pub freelist_count: i64,
    pub sessions: i64,
    pub messages: i64,
}

/// A match found while searching the stored conversations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    pub session_id: String,
    pub session_name: String,
    pub role: String,
    pub snippet: String,
}

/// A persistent note stored encrypted in the vault (Enclave's local "memory").
///
/// Memories survive across sessions and can be injected into the system prompt.
/// `local_only` memories are never sent to a provider (kept only on disk).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Memory {
    pub id: String,
    pub text: String,
    pub tags: String,
    pub kind: String,
    pub source_session: Option<String>,
    pub pinned: bool,
    pub local_only: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Handle to the encrypted SQLCipher database.
pub struct EncryptedMemory {
    conn: rusqlite::Connection,
    path: Option<std::path::PathBuf>,
}

/// Sibling path with a suffix appended (e.g. SQLite `-journal`).
fn sidecar(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    std::path::PathBuf::from(s)
}

impl EncryptedMemory {
    /// Open (creating if needed) the encrypted database at `db_path`.
    ///
    /// The key is applied with SQLCipher raw-key syntax so no KDF is run twice.
    pub fn open(db_path: &Path, key: &MasterKey) -> Result<Self> {
        let conn = rusqlite::Connection::open(db_path)?;
        conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", key.to_hex()))?;
        let mut mem = Self::configure(conn)?;
        mem.path = Some(db_path.to_path_buf());
        Ok(mem)
    }

    /// An encrypted in-memory database (sub-agents: nothing touches disk).
    pub fn open_ephemeral(key: &MasterKey) -> Result<Self> {
        let conn = rusqlite::Connection::open_in_memory()?;
        conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", key.to_hex()))?;
        Self::configure(conn)
    }

    fn configure(conn: rusqlite::Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA cipher_page_size = 4096; \
             PRAGMA kdf_iter = 256000; \
             PRAGMA cipher_hmac_algorithm = HMAC_SHA512; \
             PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;",
        )?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions (\
                id TEXT PRIMARY KEY, \
                name TEXT NOT NULL, \
                created_at TEXT NOT NULL, \
                updated_at TEXT NOT NULL\
             );\
             CREATE TABLE IF NOT EXISTS messages (\
                id INTEGER PRIMARY KEY AUTOINCREMENT, \
                session_id TEXT NOT NULL, \
                role TEXT NOT NULL, \
                content TEXT NOT NULL, \
                timestamp TEXT NOT NULL, \
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE\
             );\
             CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, id);",
        )?;
        // Persistent memories (Enclave's encrypted local "supermemory").
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS memories (\
                id TEXT PRIMARY KEY, \
                text TEXT NOT NULL, \
                tags TEXT NOT NULL DEFAULT '', \
                kind TEXT NOT NULL DEFAULT 'note', \
                source_session TEXT, \
                pinned INTEGER NOT NULL DEFAULT 0, \
                local_only INTEGER NOT NULL DEFAULT 0, \
                created_at TEXT NOT NULL, \
                updated_at TEXT NOT NULL\
             );\
             CREATE INDEX IF NOT EXISTS idx_memories_updated ON memories(pinned DESC, updated_at DESC);",
        )?;
        // Migration: tool-call metadata column (added in 0.2).
        let has_meta: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('messages') WHERE name = 'meta'",
            [],
            |r| r.get(0),
        )?;
        if has_meta == 0 {
            conn.execute_batch(
                "ALTER TABLE messages ADD COLUMN meta TEXT NOT NULL DEFAULT '';",
            )?;
        }
        Ok(Self { conn, path: None })
    }

    /// Path of the on-disk encrypted database, if this is not ephemeral.
    pub fn db_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Total size on disk of the encrypted database (+ journal/WAL sidecars).
    pub fn disk_bytes(&self) -> u64 {
        let Some(path) = &self.path else {
            return 0;
        };
        let mut total = 0u64;
        for candidate in [path.clone(), sidecar(path, "-journal"), sidecar(path, "-wal")] {
            if let Ok(m) = std::fs::metadata(&candidate) {
                total += m.len();
            }
        }
        total
    }

    /// Create a new session and return its id.
    pub fn create_session(&self, name: &str) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO sessions (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
            rusqlite::params![id, name, now],
        )?;
        Ok(id)
    }

    /// Whether a session id exists.
    pub fn session_exists(&self, id: &str) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(1) FROM sessions WHERE id = ?1",
            rusqlite::params![id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Rename a session.
    pub fn rename_session(&self, id: &str, name: &str) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let rows = self.conn.execute(
            "UPDATE sessions SET name = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![name, now, id],
        )?;
        if rows == 0 {
            return Err(EnclaveError::other("session not found"));
        }
        Ok(())
    }

    /// Persist a single message (role is one of system/user/assistant).
    pub fn save_message(&self, session_id: &str, role: &str, content: &str) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO messages (session_id, role, content, timestamp) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![session_id, role, content, now],
        )?;
        self.conn.execute(
            "UPDATE sessions SET updated_at = ?1 WHERE id = ?2",
            rusqlite::params![now, session_id],
        )?;
        Ok(())
    }

    /// Persist a full [`Message`], including tool-call metadata.
    pub fn save_message_full(&self, session_id: &str, message: &Message) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let meta = encode_meta(message)?;
        self.conn.execute(
            "INSERT INTO messages (session_id, role, content, timestamp, meta) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![session_id, message.role.as_str(), message.content, now, meta],
        )?;
        self.conn.execute(
            "UPDATE sessions SET updated_at = ?1 WHERE id = ?2",
            rusqlite::params![now, session_id],
        )?;
        Ok(())
    }

    /// Fetch the most recent `limit` messages in chronological order.
    pub fn get_history(&self, session_id: &str, limit: usize) -> Result<Vec<Message>> {
        let mut stmt = self.conn.prepare(
            "SELECT role, content, meta FROM (\
                SELECT id, role, content, meta FROM messages \
                WHERE session_id = ?1 ORDER BY id DESC LIMIT ?2\
              ) ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(rusqlite::params![session_id, limit as i64], |row| {
            let role: String = row.get(0)?;
            let content: String = row.get(1)?;
            let meta: String = row.get(2)?;
            Ok(decode_meta(Role::parse(&role), content, &meta))
        })?;
        let mut history = Vec::new();
        for row in rows {
            history.push(row?);
        }
        Ok(history)
    }

    /// List sessions, most recently updated first.
    pub fn list_sessions(&self) -> Result<Vec<SessionInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT s.id, s.name, s.updated_at, COUNT(m.id) \
             FROM sessions s LEFT JOIN messages m ON m.session_id = s.id \
             GROUP BY s.id ORDER BY s.updated_at DESC",
        )?;
        let rows = stmt.query_map(rusqlite::params![], |row| {
            Ok(SessionInfo {
                id: row.get(0)?,
                name: row.get(1)?,
                updated_at: row.get(2)?,
                message_count: row.get(3)?,
            })
        })?;
        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(row?);
        }
        Ok(sessions)
    }

    /// Delete a session and all of its messages.
    pub fn delete_session(&self, id: &str) -> Result<()> {        self.conn.execute(
            "DELETE FROM messages WHERE session_id = ?1",
            rusqlite::params![id],
        )?;
        self.conn.execute(
            "DELETE FROM sessions WHERE id = ?1",
            rusqlite::params![id],
        )?;
        Ok(())
    }

    /// Delete the most recent `n` messages of a session (used by undo/retry).
    /// Returns the number of rows removed.
    pub fn delete_last_messages(&self, session_id: &str, n: usize) -> Result<usize> {
        if n == 0 {
            return Ok(0);
        }
        let removed = self.conn.execute(
            "DELETE FROM messages WHERE id IN (\
                SELECT id FROM messages WHERE session_id = ?1 ORDER BY id DESC LIMIT ?2\
             )",
            rusqlite::params![session_id, n as i64],
        )?;
        self.conn.execute(
            "UPDATE sessions SET updated_at = ?1 WHERE id = ?2",
            rusqlite::params![chrono::Utc::now().to_rfc3339(), session_id],
        )?;
        Ok(removed)
    }

    /// Delete all messages of a session, keeping the session itself.
    /// Returns the number of rows removed.
    pub fn clear_session_messages(&self, session_id: &str) -> Result<usize> {
        let removed = self.conn.execute(
            "DELETE FROM messages WHERE session_id = ?1",
            rusqlite::params![session_id],
        )?;
        Ok(removed)
    }

    /// Search every stored message for `query` (substring, case-insensitive).
    /// Most recently updated sessions come first. `limit` caps the hits.
    pub fn search_messages(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
        let query = query.trim();
        if query.is_empty() {
            return Ok(Vec::new());
        }
        let escaped = query
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{escaped}%");
        let mut stmt = self.conn.prepare(
            "SELECT m.session_id, s.name, m.role, m.content \
             FROM messages m JOIN sessions s ON m.session_id = s.id \
             WHERE m.content LIKE ?1 ESCAPE '\\' \
             ORDER BY s.updated_at DESC, m.id ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![pattern, limit as i64], |row| {
            let content: String = row.get(3)?;
            Ok(SearchHit {
                session_id: row.get(0)?,
                session_name: row.get(1)?,
                role: row.get(2)?,
                snippet: snippet_for(&content, query),
            })
        })?;
        let mut hits = Vec::new();
        for row in rows {
            hits.push(row?);
        }
        Ok(hits)
    }

    /// Delete every session (and, by cascade/loop, all messages).
    /// Returns the number of deleted sessions.
    pub fn delete_all_sessions(&self) -> Result<usize> {        let sessions = self.list_sessions()?;
        for s in &sessions {
            self.delete_session(&s.id)?;
        }
        Ok(sessions.len())
    }

    /// Compact the encrypted database: freed pages are removed from the file,
    /// so deleted ciphertext no longer lingers on disk.
    pub fn vacuum(&self) -> Result<()> {
        self.conn.execute_batch("VACUUM;")?;
        Ok(())
    }

    /// Collect decrypted-content and file-layout statistics.
    ///
    /// SQLCipher reports PRAGMA values as TEXT, so every metric is read as a
    /// string and parsed defensively.
    pub fn stats(&self) -> Result<DbStats> {
        let read_pragma = |name: &str| -> Result<i64> {
            let sql = format!("PRAGMA {name}");
            match self.conn.query_row(&sql, [], |r| r.get::<_, String>(0)) {
                Ok(text) => Ok(text.trim().parse().unwrap_or(0)),
                Err(rusqlite::Error::InvalidColumnType(..)) => {
                    // Some PRAGMAs report as INTEGER.
                    Ok(self.conn.query_row(&sql, [], |r| r.get::<_, i64>(0))?)
                }
                Err(e) => Err(e.into()),
            }
        };
        let sessions: i64 =
            self.conn.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))?;
        let messages: i64 =
            self.conn.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?;
        Ok(DbStats {
            page_size: read_pragma("page_size")?,
            page_count: read_pragma("page_count")?,
            freelist_count: read_pragma("freelist_count")?,
            sessions,
            messages,
        })
    }

    // --- Persistent memories (Enclave's local, encrypted "supermemory") ---

    /// The column list shared by every `memories` query (keeps `map_memory` aligned).
    const MEMORY_COLS: &'static str =
        "id, text, tags, kind, source_session, pinned, local_only, created_at, updated_at";

    /// Store a new memory and return its id.
    pub fn add_memory(
        &self,
        text: &str,
        tags: &str,
        kind: &str,
        source_session: Option<&str>,
        local_only: bool,
    ) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO memories \
                (id, text, tags, kind, source_session, pinned, local_only, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?7)",
            rusqlite::params![id, text, tags, kind, source_session, local_only as i64, now],
        )?;
        Ok(id)
    }

    /// List memories, pinned first then most recently updated. `limit` caps the rows.
    pub fn list_memories(&self, limit: usize) -> Result<Vec<Memory>> {
        let sql = format!(
            "SELECT {} FROM memories ORDER BY pinned DESC, updated_at DESC LIMIT ?1",
            Self::MEMORY_COLS
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params![limit as i64], map_memory)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Memories eligible for injection into the prompt: excludes `local_only`.
    pub fn injectable_memories(&self, limit: usize) -> Result<Vec<Memory>> {
        let sql = format!(
            "SELECT {} FROM memories WHERE local_only = 0 \
             ORDER BY pinned DESC, updated_at DESC LIMIT ?1",
            Self::MEMORY_COLS
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params![limit as i64], map_memory)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Search memories by substring over text and tags.
    pub fn search_memories(&self, query: &str, limit: usize) -> Result<Vec<Memory>> {
        let query = query.trim();
        if query.is_empty() {
            return Ok(Vec::new());
        }
        let pattern = format!("%{}%", escape_like(query));
        let sql = format!(
            "SELECT {} FROM memories \
             WHERE text LIKE ?1 ESCAPE '\\' OR tags LIKE ?1 ESCAPE '\\' \
             ORDER BY pinned DESC, updated_at DESC LIMIT ?2",
            Self::MEMORY_COLS
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params![pattern, limit as i64], map_memory)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Fetch a single memory by id.
    pub fn get_memory(&self, id: &str) -> Result<Option<Memory>> {
        let sql = format!("SELECT {} FROM memories WHERE id = ?1", Self::MEMORY_COLS);
        let found = self.conn.query_row(&sql, rusqlite::params![id], map_memory).optional()?;
        Ok(found)
    }

    /// Pin or unpin a memory. Returns whether a row was updated.
    pub fn set_memory_pinned(&self, id: &str, pinned: bool) -> Result<bool> {
        let now = chrono::Utc::now().to_rfc3339();
        let rows = self.conn.execute(
            "UPDATE memories SET pinned = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![pinned as i64, now, id],
        )?;
        Ok(rows > 0)
    }

    /// Replace the text and tags of an existing memory. Returns whether it existed.
    pub fn update_memory(&self, id: &str, text: &str, tags: &str) -> Result<bool> {
        let now = chrono::Utc::now().to_rfc3339();
        let rows = self.conn.execute(
            "UPDATE memories SET text = ?1, tags = ?2, updated_at = ?3 WHERE id = ?4",
            rusqlite::params![text, tags, now, id],
        )?;
        Ok(rows > 0)
    }

    /// Delete a memory by id. Returns whether it existed.
    pub fn delete_memory(&self, id: &str) -> Result<bool> {
        let rows = self
            .conn
            .execute("DELETE FROM memories WHERE id = ?1", rusqlite::params![id])?;
        Ok(rows > 0)
    }

    /// Delete every memory whose text or tags contain `query`. Returns rows removed.
    pub fn delete_memories_matching(&self, query: &str) -> Result<usize> {
        let query = query.trim();
        if query.is_empty() {
            return Ok(0);
        }
        let pattern = format!("%{}%", escape_like(query));
        let rows = self.conn.execute(
            "DELETE FROM memories WHERE text LIKE ?1 ESCAPE '\\' OR tags LIKE ?1 ESCAPE '\\'",
            rusqlite::params![pattern],
        )?;
        Ok(rows)
    }

    /// Number of stored memories.
    pub fn memory_count(&self) -> Result<i64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))?;
        Ok(n)
    }
}

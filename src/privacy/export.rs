//! Encrypted session export/import (portable `.enclave` files).
//!
//! File layout: `MAGIC || version || salt || nonce||ciphertext`
//! where the ciphertext is an AES-256-GCM encryption of a JSON payload.
//! The key is derived with PBKDF2-HMAC-SHA256 from a dedicated export
//! password and a fresh random salt written into the file itself.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::core::message::Message;
use crate::error::{EnclaveError, Result};
use crate::privacy::crypto::{decrypt, derive_key_pbkdf2, encrypt, random_bytes};
use crate::privacy::memory::EncryptedMemory;

const MAGIC: &[u8] = b"ENCLAVE-EXPORT-";
const VERSION: u8 = 1;
const SALT_LEN: usize = 32;
/// Generous cap so `get_history` returns the whole session.
const HISTORY_LIMIT: usize = 1_000_000;

#[derive(Serialize, Deserialize)]
struct ExportPayload {
    version: u8,
    session_id: String,
    session_name: String,
    messages: Vec<Message>,
}

/// Export a session to an encrypted file. Returns the number of messages written.
pub fn export_session(
    memory: &EncryptedMemory,
    session_id: &str,
    out_path: &Path,
    password: &str,
) -> Result<usize> {
    let sessions = memory.list_sessions()?;
    let info = sessions
        .iter()
        .find(|s| s.id == session_id)
        .ok_or_else(|| EnclaveError::other(format!("session '{session_id}' not found")))?;

    let messages = memory.get_history(session_id, HISTORY_LIMIT)?;
    let payload = ExportPayload {
        version: VERSION,
        session_id: session_id.to_string(),
        session_name: info.name.clone(),
        messages: messages.clone(),
    };

    let json = serde_json::to_vec_pretty(&payload)?;
    let salt = random_bytes(SALT_LEN);
    let key = derive_key_pbkdf2(password, &salt)?;
    let encrypted = encrypt(&key, &json)?;

    let mut file = Vec::with_capacity(MAGIC.len() + 1 + SALT_LEN + encrypted.len());
    file.extend_from_slice(MAGIC);
    file.push(VERSION);
    file.extend_from_slice(&salt);
    file.extend_from_slice(&encrypted);

    std::fs::write(out_path, &file)?;
    Ok(messages.len())
}

/// Import a session from an encrypted file, creating a NEW session.
/// Returns `(new_session_id, message_count)`.
pub fn import_session(
    memory: &EncryptedMemory,
    path: &Path,
    password: &str,
) -> Result<(String, usize)> {
    let raw = std::fs::read(path)
        .map_err(|e| EnclaveError::other(format!("cannot read {}: {e}", path.display())))?;

    let header_len = MAGIC.len() + 1 + SALT_LEN;
    if raw.len() < header_len + 12 {
        return Err(EnclaveError::other("file is not a valid Enclave export"));
    }
    if &raw[..MAGIC.len()] != MAGIC {
        return Err(EnclaveError::other("file is not a valid Enclave export"));
    }
    let version = raw[MAGIC.len()];
    if version != VERSION {
        return Err(EnclaveError::other(format!(
            "unsupported export version {version}"
        )));
    }

    let salt = &raw[MAGIC.len() + 1..header_len];
    let encrypted = &raw[header_len..];

    let key = derive_key_pbkdf2(password, salt)?;
    let json = decrypt(&key, encrypted)
        .map_err(|_| EnclaveError::other("wrong password or corrupted export file"))?;

    let payload: ExportPayload = serde_json::from_slice(&json)?;

    let new_id = memory.create_session(&payload.session_name)?;
    for m in &payload.messages {
        memory.save_message(&new_id, m.role.as_str(), &m.content)?;
    }
    Ok((new_id, payload.messages.len()))
}
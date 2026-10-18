//! Privacy layer: encrypted memory, secure key storage and cryptography.

pub mod crypto;
pub mod export;
pub mod exposure;
pub mod guard;
pub mod keys;
pub mod memory;
pub mod policy;
pub mod secure;
pub mod vault;

pub use crypto::{decrypt, derive_key_pbkdf2, encrypt, random_bytes, Kdf};
pub use exposure::{blast_radius, privacy_score, BlastRadius, PrivacyScore};
pub use guard::{scan, Finding, FindingKind, Redactor};
pub use keys::SecureCredentials;
pub use memory::{
    BranchNode, DbStats, Decision, EgressEntry, EgressSummary, EncryptedMemory, Memory, RagChunk,
    SearchHit, SessionInfo,
};
pub use vault::{MasterKey, Vault};

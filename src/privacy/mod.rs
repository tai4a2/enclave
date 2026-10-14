//! Privacy layer: encrypted memory, secure key storage and cryptography.

pub mod crypto;
pub mod exposure;
pub mod export;
pub mod guard;
pub mod keys;
pub mod memory;
pub mod policy;
pub mod secure;
pub mod vault;

pub use crypto::{Kdf, decrypt, derive_key_pbkdf2, encrypt, random_bytes};
pub use guard::{Finding, FindingKind, Redactor, scan};
pub use keys::SecureCredentials;
pub use exposure::{BlastRadius, PrivacyScore, blast_radius, privacy_score};
pub use memory::{
    BranchNode, DbStats, Decision, EgressEntry, EgressSummary, EncryptedMemory, Memory, RagChunk,
    SearchHit, SessionInfo,
};
pub use vault::{MasterKey, Vault};

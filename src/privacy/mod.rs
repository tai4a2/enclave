//! Privacy layer: encrypted memory, secure key storage and cryptography.

pub mod crypto;
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
pub use memory::{BranchNode, DbStats, EgressEntry, EncryptedMemory, Memory, RagChunk, SearchHit, SessionInfo};
pub use vault::{MasterKey, Vault};

//! Enclave — privacy-first AI CLI with encrypted memory.
//!
//! This crate exposes the building blocks used by the `enclave` binary. The
//! guiding principle is *zero plaintext at rest*: chat history lives in an
//! AES-256 encrypted SQLCipher database and API keys live in the OS keychain.

pub mod cli;
pub mod clipboard;
pub mod config;
pub mod core;
pub mod error;
pub mod privacy;
pub mod providers;
pub mod tui;
pub mod web;

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

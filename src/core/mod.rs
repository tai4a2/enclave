//! Core chat engine, sessions and message model.

pub mod agents;
pub mod builtin_tools;
pub mod engine;
pub mod message;
pub mod session;
pub mod tools;

pub use agents::AgentRunner;
pub use engine::ChatEngine;
pub use message::{Message, Role, ToolCall};
pub use session::Session;
pub use tools::{Proposal, ToolOutput};

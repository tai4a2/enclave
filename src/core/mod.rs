//! Core chat engine, sessions and message model.

pub mod agents;
pub mod attachment;
pub mod builtin_tools;
pub mod diff;
pub mod engine;
pub mod message;
pub mod session;
pub mod tools;

pub use agents::AgentRunner;
pub use attachment::{Attachment, AttachmentKind};
pub use builtin_tools::FileChange;
pub use diff::{DiffKind, DiffLine};
pub use engine::{AgentStep, ApprovedGate, ChatEngine, ToolDecision, ToolGate};
pub use message::{Message, Role, ToolCall};
pub use session::Session;
pub use tools::{Proposal, ToolOutput};

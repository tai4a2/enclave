//! Core chat engine, sessions and message model.

pub mod agents;
pub mod attachment;
pub mod builtin_tools;
pub mod checkpoint;
pub mod commands;
pub mod diff;
pub mod dlp;
pub mod engine;
pub mod export;
pub mod hooks;
pub mod mcp;
pub mod message;
pub mod permissions;
pub mod rag;
pub mod repomap;
pub mod risk;
pub mod rules;
pub mod session;
pub mod skills;
pub mod tools;
pub mod verify;
pub mod worktree;

pub use agents::AgentRunner;
pub use attachment::{Attachment, AttachmentKind};
pub use builtin_tools::FileChange;
pub use checkpoint::{Checkpoint, CheckpointStore};
pub use commands::CustomCommand;
pub use diff::{DiffKind, DiffLine};
pub use engine::{
    AgentMode, AgentStep, ApprovedGate, ChatEngine, ContextPart, ContextReport, ToolDecision,
    ToolGate,
};
pub use hooks::{HookOutcome, Hooks};
pub use message::{Message, Role, ToolCall};
pub use repomap::RepoMap;
pub use risk::{Risk, RiskHit};
pub use session::Session;
pub use skills::{Skill, SkillsRegistry};
pub use tools::{Proposal, ToolOutput};
pub use verify::{VerifyCommand, VerifyReport};
pub use worktree::Worktree;

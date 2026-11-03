//! AI coding agent context briefing and built-in Model Context Protocol (MCP) server.
//!
//! Provides dynamic `SKILL.md` repository scaffolding, `dotler ai` one-shot briefings,
//! and a stateless JSON-RPC 2.0 stdio MCP server exposing 7 dotfile operations.

pub mod briefing;
pub mod mcp;

pub use briefing::{EnvironmentSnapshot, render_briefing, scaffold_skill_md};
pub use mcp::{
    McpErrorObject, McpRequest, McpResponse, McpToolDefinition, ToolCallResult, ToolContent,
    list_tools, run_mcp_server,
};

/// Agent subsystem error types.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    Config(#[from] crate::config::ConfigError),

    #[error("Lock error: {0}")]
    Lock(#[from] crate::config::LockError),

    #[error("State error: {0}")]
    State(#[from] crate::config::StateError),

    #[error("Engine error: {0}")]
    Engine(#[from] crate::engine::EngineError),

    #[error("Keyring error: {0}")]
    Keyring(#[from] crate::crypto::keyring::KeyringError),

    #[error("Vault error: {0}")]
    Vault(#[from] crate::crypto::vault::VaultError),

    #[error("Protocol error: {0}")]
    Protocol(String),
}

//! AI coding agent context briefing and built-in Model Context Protocol (MCP) server.
//!
//! Provides `dotler ai` one-shot briefings, onboarding hints for `dotler.toml` and `dotler init`,
//! and a stateless JSON-RPC 2.0 stdio MCP server exposing 7 dotfile operations.

pub mod briefing;
pub mod mcp;

pub use briefing::{
    DEFAULT_DOTLER_TOML, DOTLER_TOML_AI_HINT, EnvironmentSnapshot, INIT_AI_HINT, render_briefing,
};
pub use mcp::{
    McpErrorObject, McpRequest, McpResponse, McpToolDefinition, ToolCallResult, ToolContent,
    list_tools, run_mcp_server,
};

/// Agent subsystem error types.
#[derive(Debug)]
pub enum AgentError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Config(crate::config::ConfigError),
    Lock(crate::config::LockError),
    State(crate::config::StateError),
    Engine(crate::engine::EngineError),
    Keyring(crate::crypto::keyring::KeyringError),
    Vault(crate::crypto::vault::VaultError),
    Protocol(String),
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Json(e) => write!(f, "JSON serialization error: {e}"),
            Self::Config(e) => write!(f, "Configuration error: {e}"),
            Self::Lock(e) => write!(f, "Lock error: {e}"),
            Self::State(e) => write!(f, "State error: {e}"),
            Self::Engine(e) => write!(f, "Engine error: {e}"),
            Self::Keyring(e) => write!(f, "Keyring error: {e}"),
            Self::Vault(e) => write!(f, "Vault error: {e}"),
            Self::Protocol(m) => write!(f, "Protocol error: {m}"),
        }
    }
}

impl std::error::Error for AgentError {}

impl From<std::io::Error> for AgentError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for AgentError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<crate::config::ConfigError> for AgentError {
    fn from(e: crate::config::ConfigError) -> Self {
        Self::Config(e)
    }
}

impl From<crate::config::LockError> for AgentError {
    fn from(e: crate::config::LockError) -> Self {
        Self::Lock(e)
    }
}

impl From<crate::config::StateError> for AgentError {
    fn from(e: crate::config::StateError) -> Self {
        Self::State(e)
    }
}

impl From<crate::engine::EngineError> for AgentError {
    fn from(e: crate::engine::EngineError) -> Self {
        Self::Engine(e)
    }
}

impl From<crate::crypto::keyring::KeyringError> for AgentError {
    fn from(e: crate::crypto::keyring::KeyringError) -> Self {
        Self::Keyring(e)
    }
}

impl From<crate::crypto::vault::VaultError> for AgentError {
    fn from(e: crate::crypto::vault::VaultError) -> Self {
        Self::Vault(e)
    }
}

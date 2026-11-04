//! Execution and dotfile synchronization engine.
//!
//! Provides 3-way synchronization, atomic staging, sequential write-ahead logging (WAL),
//! in-place format tidying, and remote Git operations.

pub mod remote;
pub mod sync;

pub use remote::{
    BACKUPS_DIR_NAME, CloneReport, GroupSelector, InstallReport, PathOverride,
    REMOTE_TOML_FETCH_MAX_BYTES, RemoteGroupInfo, RemoteManifestSummary, RemoteRepoSummary,
    RemoteRepoUrl, STAGING_CLONE_PREFIX, UninstallReport, clone_repo, install_remote, list_remote,
    parse_url, uninstall_remote,
};
pub use sync::{
    ATOMIC_REPLACE_RETRIES, FileActionPlan, FileSyncStatus, SyncEngine, SyncReport,
    TMP_FILE_PREFIX, TidyOrphanPolicy, TidyReport, atomic_write_file, export_files, import_files,
    plan, tidy,
};

use std::path::PathBuf;

/// Top-level error enum for all engine synchronization and remote operations.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("Failed to acquire dotler.lock: timed out after {timeout_ms}ms")]
    LockTimeout { timeout_ms: u64 },

    #[error("Vault is locked: {reason}")]
    VaultLocked { reason: String },

    #[error("Local modification conflict on '{path}': {reason}")]
    SyncConflict { path: PathBuf, reason: String },

    #[error("Encryption mismatch on '{path}': {reason}")]
    EncryptionMismatch { path: PathBuf, reason: String },

    #[error("Security policy violation on '{path}': {reason}")]
    HardBlockedPath { path: PathBuf, reason: String },

    #[error("Remote payload exceeded {limit_bytes} bytes (got {size_bytes} bytes)")]
    PayloadExceeded {
        size_bytes: usize,
        limit_bytes: usize,
    },

    #[error("Invalid remote URL '{url}': {reason}")]
    InvalidUrlFormat { url: String, reason: String },

    #[error("Git {operation} failed: {message}")]
    GitError { operation: String, message: String },

    #[error("Group '{group}' not found in repository (available: {available:?})")]
    GroupNotFound {
        group: String,
        available: Vec<String>,
    },

    #[error("Missing remote dotler.toml in repository '{url}'")]
    MissingRemoteToml { url: String },

    #[error("File not found: '{path}'")]
    FileNotFound { path: PathBuf },

    #[error("Atomic replace failed for '{0}'")]
    AtomicReplaceFailed(String),

    #[error("Configuration error: {0}")]
    Config(#[from] crate::config::ConfigError),

    #[error("State ledger error: {0}")]
    State(#[from] crate::config::StateError),

    #[error("Cryptographic error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),

    #[error("Vault error: {0}")]
    Vault(#[from] crate::crypto::vault::VaultError),

    #[error("Lock error: {0}")]
    Lock(#[from] crate::config::LockError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl EngineError {
    /// Maps the error to a deterministic process exit code (0..4).
    pub fn exit_code(&self) -> i32 {
        match self {
            EngineError::SyncConflict { .. } | EngineError::EncryptionMismatch { .. } => 1,
            EngineError::HardBlockedPath { .. } => 3,
            EngineError::LockTimeout { .. } | EngineError::VaultLocked { .. } => 4,
            EngineError::Config(e) => e.exit_code(),
            EngineError::State(e) => e.exit_code(),
            EngineError::Crypto(e) => e.exit_code(),
            EngineError::Vault(e) => e.exit_code(),
            EngineError::Lock(e) => e.exit_code(),
            _ => 2,
        }
    }

    /// Machine-readable error code for structured JSON payloads and AI agents.
    pub fn error_code(&self) -> &'static str {
        match self {
            EngineError::LockTimeout { .. } => "LOCK_TIMEOUT",
            EngineError::VaultLocked { .. } => "VAULT_LOCKED",
            EngineError::SyncConflict { .. } => "LOCAL_EDIT_CONFLICT",
            EngineError::EncryptionMismatch { .. } => "ENCRYPTION_MISMATCH",
            EngineError::HardBlockedPath { .. } => "SECURITY_BLOCKED",
            EngineError::PayloadExceeded { .. } => "PAYLOAD_EXCEEDED",
            EngineError::InvalidUrlFormat { .. } => "INVALID_URL",
            EngineError::GitError { .. } => "GIT_ERROR",
            EngineError::GroupNotFound { .. } => "GROUP_NOT_FOUND",
            EngineError::MissingRemoteToml { .. } => "MISSING_MANIFEST",
            EngineError::FileNotFound { .. } => "FILE_NOT_FOUND",
            EngineError::AtomicReplaceFailed(_) => "IO_ERROR",
            EngineError::Config(crate::config::ConfigError::HardBlockedPath { .. }) => {
                "SECURITY_BLOCKED"
            }
            EngineError::Config(_) => "CONFIG_ERROR",
            EngineError::State(_) => "STATE_ERROR",
            EngineError::Crypto(_) | EngineError::Vault(_) => "CRYPTO_ERROR",
            EngineError::Lock(_) => "LOCK_ERROR",
            EngineError::Io(_) => "IO_ERROR",
        }
    }

    /// Actionable remediation hint for users and automated agents.
    pub fn hint(&self) -> String {
        match self {
            EngineError::LockTimeout { .. } => {
                "Another dotler process holds ~/.config/dotler/dotler.lock. Wait for it to complete or terminate stale processes.".to_string()
            }
            EngineError::VaultLocked { .. } => {
                "Run 'dotler key set' to store the passphrase in the OS keyring, or set the DOTLER_PASSPHRASE environment variable.".to_string()
            }
            EngineError::SyncConflict { path, .. } => {
                format!(
                    "File '{}' has local modifications. Run 'dotler import' to update the repository or 'dotler export --force' to overwrite.",
                    path.display()
                )
            }
            EngineError::EncryptionMismatch { path, .. } => {
                format!(
                    "File '{}' has mismatched encryption state. Run 'dotler tidy' to reconcile format with dotler.toml.",
                    path.display()
                )
            }
            EngineError::HardBlockedPath { path, .. } => {
                format!(
                    "Path '{}' violates path security rules. Ensure targets remain within home directory and contain no '..' traversal components.",
                    path.display()
                )
            }
            EngineError::PayloadExceeded { limit_bytes, .. } => {
                format!("Remote dotler.toml exceeds maximum limit of {limit_bytes} bytes (1 MiB).")
            }
            EngineError::InvalidUrlFormat { .. } => {
                "Specify a valid Git URL or supported shorthand prefix (gh:, gl:, cb:, srht:, bb:).".to_string()
            }
            EngineError::GitError { .. } => {
                "Verify the remote Git URL, network connectivity, and repository access permissions.".to_string()
            }
            EngineError::GroupNotFound { group, available } => {
                format!("Group '{group}' is not defined in dotler.toml. Available groups: {available:?}")
            }
            EngineError::MissingRemoteToml { url } => {
                format!("Repository at '{url}' does not contain a dotler.toml manifest.")
            }
            EngineError::FileNotFound { path } => {
                format!("File '{}' does not exist.", path.display())
            }
            EngineError::AtomicReplaceFailed(msg) => {
                format!("Atomic file replace failed: {msg}")
            }
            EngineError::Config(crate::config::ConfigError::MissingVaultConfig) => {
                "Run 'dotler vault init' to initialize vault encryption before syncing encrypted files.".to_string()
            }
            EngineError::Config(e) => format!("Fix configuration error: {e}"),
            EngineError::State(e) => format!("Database operation failed: {e}"),
            EngineError::Crypto(e) => format!("Cryptographic operation failed: {e}"),
            EngineError::Vault(e) => format!("Vault operation failed: {e}"),
            EngineError::Lock(e) => format!("Lock operation failed: {e}"),
            EngineError::Io(e) => format!("I/O operation failed: {e}"),
        }
    }
}

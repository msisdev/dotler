//! Execution and dotfile synchronization engine.
//!
//! Provides 3-way synchronization, atomic staging, sequential write-ahead logging (WAL),
//! in-place format tidying, observer callbacks, and remote Git operations.

pub mod check;
pub mod observer;
pub mod remote;
pub mod sync;
pub mod tidy;

pub use check::{
    CheckReport, FileActionPlan, FileSyncStatus, InitParams, InitReport, plan, run_check, run_init,
    run_status,
};
pub use observer::{
    CommandObserver, NoopObserver, PlanActionKind, PlanDirection, PlanPreviewEntry,
};
pub use remote::{
    BACKUPS_DIR_NAME, CloneReport, GroupSelector, InstallReport, PathOverride,
    REMOTE_TOML_FETCH_MAX_BYTES, RemoteGroupInfo, RemoteManifestSummary, RemoteRepoSummary,
    RemoteRepoUrl, STAGING_CLONE_PREFIX, UninstallReport, clone_repo, clone_repo_with_observer,
    install_remote, install_remote_with_observer, list_remote, parse_url, run_git_clone,
    run_git_install, run_git_ls, run_git_uninstall, uninstall_remote,
    uninstall_remote_with_observer,
};
pub use sync::{
    ATOMIC_REPLACE_RETRIES, SyncEngine, SyncReport, TMP_FILE_PREFIX, export_files, import_files,
    run_export, run_import, write_file_safe,
};
pub use tidy::{
    TidyOrphanPolicy, TidyReport, run_tidy, tidy, tidy_groups, tidy_groups_with_observer,
};

use std::path::PathBuf;

/// Top-level error enum for all engine synchronization and remote operations.
#[derive(Debug)]
pub enum EngineError {
    LockTimeout {
        timeout_ms: u64,
    },
    VaultLocked {
        reason: String,
    },
    SyncConflict {
        path: PathBuf,
        reason: String,
    },
    EncryptionMismatch {
        path: PathBuf,
        reason: String,
    },
    HardBlockedPath {
        path: PathBuf,
        reason: String,
    },
    PayloadExceeded {
        size_bytes: usize,
        limit_bytes: usize,
    },
    InvalidUrlFormat {
        url: String,
        reason: String,
    },
    GitError {
        operation: String,
        message: String,
    },
    GroupNotFound {
        group: String,
        available: Vec<String>,
    },
    MissingRemoteToml {
        url: String,
    },
    FileNotFound {
        path: PathBuf,
    },
    NonInteractiveConfirmationRequired {
        command: String,
    },
    AtomicReplaceFailed(String),
    Config(crate::config::ConfigError),
    State(crate::config::StateError),
    Crypto(crate::crypto::CryptoError),
    Vault(crate::crypto::vault::VaultError),
    Lock(crate::config::LockError),
    Io(std::io::Error),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LockTimeout { timeout_ms } => write!(
                f,
                "Failed to acquire dotler.lock: timed out after {timeout_ms}ms"
            ),
            Self::VaultLocked { reason } => write!(f, "Vault is locked: {reason}"),
            Self::SyncConflict { path, reason } => write!(
                f,
                "Local modification conflict on '{}': {reason}",
                path.display()
            ),
            Self::EncryptionMismatch { path, reason } => {
                write!(f, "Encryption mismatch on '{}': {reason}", path.display())
            }
            Self::HardBlockedPath { path, reason } => write!(
                f,
                "Security policy violation on '{}': {reason}",
                path.display()
            ),
            Self::PayloadExceeded {
                size_bytes,
                limit_bytes,
            } => write!(
                f,
                "Remote payload exceeded {limit_bytes} bytes (got {size_bytes} bytes)"
            ),
            Self::InvalidUrlFormat { url, reason } => {
                write!(f, "Invalid remote URL '{url}': {reason}")
            }
            Self::GitError { operation, message } => {
                write!(f, "Git {operation} failed: {message}")
            }
            Self::GroupNotFound { group, available } => write!(
                f,
                "Group '{group}' not found in repository (available: {available:?})"
            ),
            Self::MissingRemoteToml { url } => {
                write!(f, "Missing remote dotler.toml in repository '{url}'")
            }
            Self::FileNotFound { path } => write!(f, "File not found: '{}'", path.display()),
            Self::NonInteractiveConfirmationRequired { command } => write!(
                f,
                "Non-interactive terminal detected for '{command}': confirmation prompt cannot run without a TTY"
            ),
            Self::AtomicReplaceFailed(m) => write!(f, "Atomic replace failed for '{m}'"),
            Self::Config(e) => write!(f, "Configuration error: {e}"),
            Self::State(e) => write!(f, "State ledger error: {e}"),
            Self::Crypto(e) => write!(f, "Cryptographic error: {e}"),
            Self::Vault(e) => write!(f, "Vault error: {e}"),
            Self::Lock(e) => write!(f, "Lock error: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<crate::config::ConfigError> for EngineError {
    fn from(e: crate::config::ConfigError) -> Self {
        Self::Config(e)
    }
}

impl From<crate::config::StateError> for EngineError {
    fn from(e: crate::config::StateError) -> Self {
        Self::State(e)
    }
}

impl From<crate::crypto::CryptoError> for EngineError {
    fn from(e: crate::crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<crate::crypto::vault::VaultError> for EngineError {
    fn from(e: crate::crypto::vault::VaultError) -> Self {
        Self::Vault(e)
    }
}

impl From<crate::config::LockError> for EngineError {
    fn from(e: crate::config::LockError) -> Self {
        Self::Lock(e)
    }
}

impl From<std::io::Error> for EngineError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
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
            EngineError::NonInteractiveConfirmationRequired { .. } => "CONFIRMATION_REQUIRED",
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
                "Specify a valid Git URL or supported provider prefix (gh:/github:, gl:/gitlab:, cb:/codeberg:, srht:/sourcehut:, bb:/bitbucket:).".to_string()
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
            EngineError::NonInteractiveConfirmationRequired { command } => {
                format!(
                    "Pass '-y' ('--yes') to auto-confirm or '--json' for machine-readable execution of 'dotler {command}'."
                )
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

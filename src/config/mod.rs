pub mod local;
pub mod repo;
pub mod state;

pub use local::{
    LOCAL_CONFIG_DIR, LOCAL_CONFIG_FILE, LocalConfig, RESERVED_OS_PREFIX, find_ancestor_repo_dir,
};
pub use repo::{GroupConfig, OsInfo, RepoConfig, SelectionMode, SelectionRule, VaultConfig};
pub use state::{
    ATOMIC_REPLACE_RETRIES, BACKUPS_DIR_PATH, DOTLER_LOCK_PATH, DOTLER_LOCK_POLL_INTERVAL_MS,
    DOTLER_LOCK_TIMEOUT_MS, DotlerLock, DotlerLockGuard, InstalledFileRecord,
    SQLITE_BUSY_TIMEOUT_MS, SQLITE_JOURNAL_MODE, SQLITE_SYNCHRONOUS, STATE_DB_PATH, StateDb,
    SyncedFileRecord, TMP_FILE_PREFIX, atomic_write_file,
};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("TOML syntax error: {0}")]
    TomlSyntaxError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Unknown field '{field}'. {hint}")]
    UnknownField { field: String, hint: String },

    #[error("Invalid device name '{device}': {reason}")]
    InvalidDeviceName { device: String, reason: String },

    #[error("Invalid default repository '{label}': repository is not configured in [repos]")]
    InvalidDefaultRepo { label: String },

    #[error(
        "Invalid repository label '{label}': label must contain only alphanumeric characters, dashes, and underscores"
    )]
    InvalidRepoLabel { label: String },

    #[error("Unknown repository label '{label}'")]
    UnknownRepoLabel { label: String },

    #[error(
        "Ambiguous default repository: multiple repositories configured but no default_repo specified"
    )]
    AmbiguousDefaultRepo,

    #[error("No repositories configured")]
    NoReposConfigured,

    #[error("Invalid home path '{path}': {reason}")]
    InvalidHomePath { path: String, reason: String },

    #[error("Path '{path}' is blocked by security policy: {reason}")]
    HardBlockedPath { path: String, reason: String },

    #[error("Invalid selection attribute '{attribute}' at line {line_no}. {hint}")]
    InvalidSelectionAttribute {
        attribute: String,
        line_no: usize,
        hint: String,
    },

    #[error("Unknown OS key '{key}'. {hint}")]
    UnknownOsKey { key: String, hint: String },

    #[error(
        "Missing [vault] configuration in repository manifest: encrypted files are declared but vault is not configured"
    )]
    MissingVaultConfig,

    #[error(
        "Cross-group target file collision: target path '{path}' is claimed by both group '{group1}' and group '{group2}'"
    )]
    CrossGroupFileCollision {
        path: String,
        group1: String,
        group2: String,
    },

    #[error("Atomic rename failed for '{0}'")]
    AtomicRenameFailed(String),

    #[error("Repository path not found: '{0}'")]
    RepoPathNotFound(String),
}

impl ConfigError {
    pub fn exit_code(&self) -> i32 {
        match self {
            ConfigError::HardBlockedPath { .. } => 3,
            _ => 2,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Lock error: {0}")]
    Lock(#[from] LockError),

    #[error("Transaction error: {0}")]
    Transaction(String),

    #[error("Atomic file replacement failed: {0}")]
    AtomicReplaceFailed(String),
}

impl StateError {
    pub fn exit_code(&self) -> i32 {
        match self {
            StateError::Lock(LockError::Timeout { .. }) => 4,
            _ => 2,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("Failed to acquire dotler.lock: timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    #[error("I/O error while operating on lock file: {0}")]
    Io(#[from] std::io::Error),
}

impl LockError {
    pub fn exit_code(&self) -> i32 {
        match self {
            LockError::Timeout { .. } => 4,
            LockError::Io(_) => 2,
        }
    }
}

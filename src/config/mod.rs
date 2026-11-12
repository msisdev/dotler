pub mod local;
pub mod repo;
pub mod resource;
pub mod state;

pub use local::{
    LOCAL_CONFIG_DIR, LOCAL_CONFIG_FILE, LocalConfig, RESERVED_OS_PREFIX, find_ancestor_repo_dir,
    get_local_config, resolve_repo_path_with_cwd,
};
pub use repo::{
    GroupConfig, OsInfo, RepoConfig, SelectionMode, SelectionRule, VaultConfig, get_repo_config,
};
pub use resource::Resource;
pub use state::{
    ATOMIC_REPLACE_RETRIES, BACKUPS_DIR_PATH, DOTLER_LOCK_PATH, DOTLER_LOCK_POLL_INTERVAL_MS,
    DOTLER_LOCK_TIMEOUT_MS, DotlerLock, DotlerLockGuard, InstalledFileRecord,
    SQLITE_BUSY_TIMEOUT_MS, SQLITE_JOURNAL_MODE, SQLITE_SYNCHRONOUS, STATE_DB_PATH,
    STATE_DB_SCHEMA_VERSION, StateDb, SyncedFileRecord, TMP_FILE_PREFIX, get_lock, get_state_db,
    write_file_safe,
};

#[derive(Debug)]
pub enum ConfigError {
    TomlSyntaxError(String),
    IoError(std::io::Error),
    UnknownField {
        field: String,
        hint: String,
    },
    InvalidDeviceName {
        device: String,
        reason: String,
    },
    InvalidDefaultRepo {
        label: String,
    },
    InvalidRepoLabel {
        label: String,
    },
    UnknownRepoLabel {
        label: String,
    },
    AmbiguousDefaultRepo,
    NoReposConfigured,
    InvalidHomePath {
        path: String,
        reason: String,
    },
    HardBlockedPath {
        path: String,
        reason: String,
    },
    InvalidSelectionAttribute {
        attribute: String,
        line_no: usize,
        hint: String,
    },
    UnknownOsKey {
        key: String,
        hint: String,
    },
    MissingVaultConfig,
    CrossGroupFileCollision {
        path: String,
        group1: String,
        group2: String,
    },
    AtomicRenameFailed(String),
    RepoPathNotFound(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TomlSyntaxError(m) => write!(f, "TOML syntax error: {m}"),
            Self::IoError(e) => write!(f, "I/O error: {e}"),
            Self::UnknownField { field, hint } => write!(f, "Unknown field '{field}'. {hint}"),
            Self::InvalidDeviceName { device, reason } => {
                write!(f, "Invalid device name '{device}': {reason}")
            }
            Self::InvalidDefaultRepo { label } => write!(
                f,
                "Invalid default repository '{label}': repository is not configured in [repos]"
            ),
            Self::InvalidRepoLabel { label } => write!(
                f,
                "Invalid repository label '{label}': label must contain only alphanumeric characters, dashes, and underscores"
            ),
            Self::UnknownRepoLabel { label } => write!(f, "Unknown repository label '{label}'"),
            Self::AmbiguousDefaultRepo => write!(
                f,
                "Ambiguous default repository: multiple repositories configured but no default_repo specified"
            ),
            Self::NoReposConfigured => write!(f, "No repositories configured"),
            Self::InvalidHomePath { path, reason } => {
                write!(f, "Invalid home path '{path}': {reason}")
            }
            Self::HardBlockedPath { path, reason } => {
                write!(f, "Path '{path}' is blocked by security policy: {reason}")
            }
            Self::InvalidSelectionAttribute {
                attribute,
                line_no,
                hint,
            } => write!(
                f,
                "Invalid selection attribute '{attribute}' at line {line_no}. {hint}"
            ),
            Self::UnknownOsKey { key, hint } => write!(f, "Unknown OS key '{key}'. {hint}"),
            Self::MissingVaultConfig => write!(
                f,
                "Missing vault configuration in repository manifest: encrypted files are declared but vault is not configured"
            ),
            Self::CrossGroupFileCollision {
                path,
                group1,
                group2,
            } => write!(
                f,
                "Cross-group target file collision: target path '{path}' is claimed by both group '{group1}' and group '{group2}'"
            ),
            Self::AtomicRenameFailed(m) => write!(f, "Atomic rename failed for '{m}'"),
            Self::RepoPathNotFound(m) => write!(f, "Repository path not found: '{m}'"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl ConfigError {
    pub fn exit_code(&self) -> i32 {
        match self {
            ConfigError::HardBlockedPath { .. } => 3,
            _ => 2,
        }
    }
}

#[derive(Debug)]
pub enum StateError {
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
    Lock(LockError),
    Transaction(String),
    AtomicReplaceFailed(String),
    UnsupportedSchemaVersion { found: u32, max_supported: u32 },
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "SQLite error: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Lock(e) => write!(f, "Lock error: {e}"),
            Self::Transaction(m) => write!(f, "Transaction error: {m}"),
            Self::AtomicReplaceFailed(m) => write!(f, "Atomic file replacement failed: {m}"),
            Self::UnsupportedSchemaVersion {
                found,
                max_supported,
            } => write!(
                f,
                "Unsupported state.db schema version {found} (maximum supported version is {max_supported})"
            ),
        }
    }
}

impl std::error::Error for StateError {}

impl From<rusqlite::Error> for StateError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

impl From<std::io::Error> for StateError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<LockError> for StateError {
    fn from(e: LockError) -> Self {
        Self::Lock(e)
    }
}

impl StateError {
    pub fn exit_code(&self) -> i32 {
        match self {
            StateError::Lock(LockError::Timeout { .. }) => 4,
            _ => 2,
        }
    }
}

#[derive(Debug)]
pub enum LockError {
    Timeout { timeout_ms: u64 },
    Io(std::io::Error),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout { timeout_ms } => write!(
                f,
                "Failed to acquire dotler.lock: timed out after {timeout_ms}ms"
            ),
            Self::Io(e) => write!(f, "I/O error while operating on lock file: {e}"),
        }
    }
}

impl std::error::Error for LockError {}

impl From<std::io::Error> for LockError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl LockError {
    pub fn exit_code(&self) -> i32 {
        match self {
            LockError::Timeout { .. } => 4,
            LockError::Io(_) => 2,
        }
    }
}

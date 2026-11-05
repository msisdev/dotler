use std::cell::OnceCell;

pub mod local;
pub mod repo;
pub mod state;

pub use local::{
    LOCAL_CONFIG_DIR, LOCAL_CONFIG_FILE, LocalConfig, RESERVED_OS_PREFIX, find_ancestor_repo_dir,
    get_local_config, resolve_repo_path_with_cwd,
};
pub use repo::{
    GroupConfig, OsInfo, RepoConfig, SelectionMode, SelectionRule, VaultConfig, get_repo_config,
};
pub use state::{
    ATOMIC_REPLACE_RETRIES, BACKUPS_DIR_PATH, DOTLER_LOCK_PATH, DOTLER_LOCK_POLL_INTERVAL_MS,
    DOTLER_LOCK_TIMEOUT_MS, DotlerLock, DotlerLockGuard, InstalledFileRecord,
    SQLITE_BUSY_TIMEOUT_MS, SQLITE_JOURNAL_MODE, SQLITE_SYNCHRONOUS, STATE_DB_PATH, StateDb,
    SyncedFileRecord, TMP_FILE_PREFIX, atomic_write_file, get_state_db,
};

/// Generic lazy resource provider interface.
///
/// Underlying resources (configuration files, SQLite connections, OS keyring secrets)
/// are accessed only on the first call to [`Provider::get`], and updated via [`Provider::set`].
pub trait Provider<T> {
    type Error;

    fn get(&self) -> Result<&T, Self::Error>;
    fn set(&mut self, value: T) -> Result<(), Self::Error>;
}

type ResourceLoader<T, E> = Box<dyn Fn() -> Result<T, E>>;
type ResourceSaver<T, E> = Box<dyn Fn(&T) -> Result<(), E>>;

/// Functional lazy resource container backed by [`OnceCell`] and `loader`/`saver` closures.
pub struct Resource<T, E> {
    cache: OnceCell<T>,
    loader: ResourceLoader<T, E>,
    saver: ResourceSaver<T, E>,
}

impl<T, E> Resource<T, E> {
    pub fn new<L, S>(loader: L, saver: S) -> Self
    where
        L: Fn() -> Result<T, E> + 'static,
        S: Fn(&T) -> Result<(), E> + 'static,
    {
        Self {
            cache: OnceCell::new(),
            loader: Box::new(loader),
            saver: Box::new(saver),
        }
    }
}

impl<T, E> Provider<T> for Resource<T, E> {
    type Error = E;

    fn get(&self) -> Result<&T, Self::Error> {
        if let Some(val) = self.cache.get() {
            return Ok(val);
        }
        let loaded = (self.loader)()?;
        let _ = self.cache.set(loaded);
        Ok(self.cache.get().expect("OnceCell initialized"))
    }

    fn set(&mut self, value: T) -> Result<(), Self::Error> {
        (self.saver)(&value)?;
        self.cache = OnceCell::from(value);
        Ok(())
    }
}

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
                "Missing [vault] configuration in repository manifest: encrypted files are declared but vault is not configured"
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
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "SQLite error: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Lock(e) => write!(f, "Lock error: {e}"),
            Self::Transaction(m) => write!(f, "Transaction error: {m}"),
            Self::AtomicReplaceFailed(m) => write!(f, "Atomic file replacement failed: {m}"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    #[test]
    fn resource_provider_loads_lazily_and_persists_via_set() {
        let load_count = Rc::new(Cell::new(0usize));
        let save_count = Rc::new(Cell::new(0usize));

        let lc = Rc::clone(&load_count);
        let sc = Rc::clone(&save_count);

        let mut res = Resource::new(
            move || {
                lc.set(lc.get() + 1);
                Ok::<String, &'static str>("initial".to_string())
            },
            move |_val: &String| {
                sc.set(sc.get() + 1);
                Ok::<(), &'static str>(())
            },
        );

        assert_eq!(load_count.get(), 0, "loader must not run before get()");
        assert_eq!(res.get().unwrap(), "initial");
        assert_eq!(load_count.get(), 1, "loader runs once on first get()");
        assert_eq!(res.get().unwrap(), "initial");
        assert_eq!(load_count.get(), 1, "subsequent get() returns cached value");

        res.set("updated".to_string()).unwrap();
        assert_eq!(save_count.get(), 1, "saver runs on set()");
        assert_eq!(res.get().unwrap(), "updated");
        assert_eq!(load_count.get(), 1, "get() after set() uses updated cache");
    }
}

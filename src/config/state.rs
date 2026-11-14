use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};

use crate::config::StateError;

pub const STATE_DB_PATH: &str = "~/.config/dotler/state.db";
pub const STATE_DB_SCHEMA_VERSION: u32 = 1;
pub use crate::config::lock::{
    ATOMIC_REPLACE_RETRIES, DOTLER_LOCK_PATH, DOTLER_LOCK_POLL_INTERVAL_MS,
    DOTLER_LOCK_TIMEOUT_MS, DotlerLock, DotlerLockGuard, TMP_FILE_PREFIX, get_lock,
    write_file_safe,
};
pub const BACKUPS_DIR_PATH: &str = "~/.config/dotler/backups";
pub const SQLITE_JOURNAL_MODE: &str = "WAL";
pub const SQLITE_SYNCHRONOUS: &str = "NORMAL";
pub const SQLITE_BUSY_TIMEOUT_MS: u64 = 5000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncedFileRecord {
    pub target_path: String,
    pub repo_label: String,
    pub group_name: String,
    pub relative_path: String,
    pub file_hash: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledFileRecord {
    pub target_path: String,
    pub repo_url: String,
    pub group_name: String,
    pub relative_path: String,
    pub file_hash: String,
    pub updated_at: i64,
    pub backup_path: Option<String>,
}

pub struct StateDb {
    conn: Mutex<Option<Connection>>,
    db_path: PathBuf,
}

impl StateDb {
    pub fn open(path: &Path) -> Result<Self, StateError> {
        if path.is_dir() {
            return Err(StateError::Io(std::io::Error::new(
                std::io::ErrorKind::IsADirectory,
                "state.db path is a directory",
            )));
        }

        let conn = if path.exists() {
            Some(Self::init_conn(path)?)
        } else {
            None
        };

        Ok(Self {
            conn: Mutex::new(conn),
            db_path: path.to_path_buf(),
        })
    }

    fn init_conn(path: &Path) -> Result<Connection, StateError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;

        conn.execute_batch(&format!(
            "PRAGMA journal_mode = {SQLITE_JOURNAL_MODE};\n\
             PRAGMA synchronous = {SQLITE_SYNCHRONOUS};\n\
             PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS};"
        ))?;

        let current_version: u32 = conn.query_row("PRAGMA user_version;", [], |row| row.get(0))?;
        if current_version > STATE_DB_SCHEMA_VERSION {
            return Err(StateError::UnsupportedSchemaVersion {
                found: current_version,
                max_supported: STATE_DB_SCHEMA_VERSION,
            });
        }

        const SCHEMA_V1_DDL: &str = "CREATE TABLE IF NOT EXISTS synced_files (
                target_path   TEXT PRIMARY KEY NOT NULL,
                repo_label    TEXT NOT NULL,
                group_name    TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                file_hash     TEXT NOT NULL,
                updated_at    INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_synced_files_group ON synced_files (repo_label, group_name);

            CREATE TABLE IF NOT EXISTS installed_files (
                target_path   TEXT PRIMARY KEY NOT NULL,
                repo_url      TEXT NOT NULL,
                group_name    TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                file_hash     TEXT NOT NULL,
                updated_at    INTEGER NOT NULL,
                backup_path   TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_installed_files_group ON installed_files (repo_url, group_name);";

        if current_version == 0 {
            conn.execute_batch(&format!(
                "BEGIN IMMEDIATE;\n\
                 {SCHEMA_V1_DDL}\n\
                 PRAGMA user_version = {STATE_DB_SCHEMA_VERSION};\n\
                 COMMIT;"
            ))?;
        } else {
            conn.execute_batch(SCHEMA_V1_DDL)?;
        }

        Ok(conn)
    }

    fn ensure_conn(&self) -> Result<std::sync::MutexGuard<'_, Option<Connection>>, StateError> {
        let mut guard = self.conn.lock().unwrap();
        if guard.is_none() {
            *guard = Some(Self::init_conn(&self.db_path)?);
        }
        Ok(guard)
    }

    fn open_existing_conn(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Option<Connection>>, StateError> {
        let mut guard = self.conn.lock().unwrap();
        if guard.is_none() && self.db_path.is_file() {
            *guard = Some(Self::init_conn(&self.db_path)?);
        }
        Ok(guard)
    }

    pub fn path(&self) -> &Path {
        &self.db_path
    }

    pub fn schema_version(&self) -> Result<u32, StateError> {
        let guard = self.open_existing_conn()?;
        let Some(conn) = guard.as_ref() else {
            return Ok(STATE_DB_SCHEMA_VERSION);
        };
        let version: u32 = conn.query_row("PRAGMA user_version;", [], |row| row.get(0))?;
        Ok(version)
    }
}

/// Creates a lazy [`Resource`] for `~/.config/dotler/state.db` (or a custom path).
pub fn get_state_db(db_path: PathBuf) -> crate::config::Resource<StateDb, StateError> {
    crate::config::Resource::new(move || StateDb::open(&db_path), |_| Ok(()))
}

fn map_synced_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SyncedFileRecord> {
    Ok(SyncedFileRecord {
        target_path: row.get(0)?,
        repo_label: row.get(1)?,
        group_name: row.get(2)?,
        relative_path: row.get(3)?,
        file_hash: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

fn map_installed_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<InstalledFileRecord> {
    Ok(InstalledFileRecord {
        target_path: row.get(0)?,
        repo_url: row.get(1)?,
        group_name: row.get(2)?,
        relative_path: row.get(3)?,
        file_hash: row.get(4)?,
        updated_at: row.get(5)?,
        backup_path: row.get(6)?,
    })
}

impl StateDb {
    pub fn upsert_synced_file(&self, record: &SyncedFileRecord) -> Result<(), StateError> {
        let guard = self.ensure_conn()?;
        let conn = guard.as_ref().unwrap();
        conn.execute(
            "INSERT INTO synced_files (target_path, repo_label, group_name, relative_path, file_hash, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(target_path) DO UPDATE SET
                 repo_label = excluded.repo_label,
                 group_name = excluded.group_name,
                 relative_path = excluded.relative_path,
                 file_hash = excluded.file_hash,
                 updated_at = excluded.updated_at;",
            params![
                record.target_path,
                record.repo_label,
                record.group_name,
                record.relative_path,
                record.file_hash,
                record.updated_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_synced_file(
        &self,
        target_path: &str,
    ) -> Result<Option<SyncedFileRecord>, StateError> {
        let guard = self.open_existing_conn()?;
        let Some(conn) = guard.as_ref() else {
            return Ok(None);
        };
        conn.query_row(
            "SELECT target_path, repo_label, group_name, relative_path, file_hash, updated_at
             FROM synced_files WHERE target_path = ?1;",
            params![target_path],
            map_synced_row,
        )
        .optional()
        .map_err(StateError::from)
    }

    pub fn list_synced_files(
        &self,
        repo_label: Option<&str>,
    ) -> Result<Vec<SyncedFileRecord>, StateError> {
        let guard = self.open_existing_conn()?;
        let Some(conn) = guard.as_ref() else {
            return Ok(Vec::new());
        };
        let (sql, filter): (&str, Vec<&str>) = match repo_label {
            Some(label) => (
                "SELECT target_path, repo_label, group_name, relative_path, file_hash, updated_at
                 FROM synced_files WHERE repo_label = ?1 ORDER BY target_path ASC;",
                vec![label],
            ),
            None => (
                "SELECT target_path, repo_label, group_name, relative_path, file_hash, updated_at
                 FROM synced_files ORDER BY target_path ASC;",
                Vec::new(),
            ),
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(filter), map_synced_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StateError::from)
    }

    pub fn remove_synced_file(&self, target_path: &str) -> Result<bool, StateError> {
        let guard = self.open_existing_conn()?;
        let Some(conn) = guard.as_ref() else {
            return Ok(false);
        };
        let affected = conn.execute(
            "DELETE FROM synced_files WHERE target_path = ?1;",
            params![target_path],
        )?;
        Ok(affected > 0)
    }

    pub fn find_orphaned_synced_files(
        &self,
        repo_label: &str,
        active_target_paths: &[String],
    ) -> Result<Vec<String>, StateError> {
        let records = self.list_synced_files(Some(repo_label))?;
        let active_set: std::collections::HashSet<&str> =
            active_target_paths.iter().map(String::as_str).collect();
        Ok(records
            .into_iter()
            .map(|r| r.target_path)
            .filter(|p| !active_set.contains(p.as_str()))
            .collect())
    }

    pub fn upsert_installed_file(&self, record: &InstalledFileRecord) -> Result<(), StateError> {
        let guard = self.ensure_conn()?;
        let conn = guard.as_ref().unwrap();
        conn.execute(
            "INSERT INTO installed_files (target_path, repo_url, group_name, relative_path, file_hash, updated_at, backup_path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(target_path) DO UPDATE SET
                 repo_url = excluded.repo_url,
                 group_name = excluded.group_name,
                 relative_path = excluded.relative_path,
                 file_hash = excluded.file_hash,
                 updated_at = excluded.updated_at,
                 backup_path = COALESCE(installed_files.backup_path, excluded.backup_path);",
            params![
                record.target_path,
                record.repo_url,
                record.group_name,
                record.relative_path,
                record.file_hash,
                record.updated_at,
                record.backup_path,
            ],
        )?;
        Ok(())
    }

    pub fn get_installed_file(
        &self,
        target_path: &str,
    ) -> Result<Option<InstalledFileRecord>, StateError> {
        let guard = self.open_existing_conn()?;
        let Some(conn) = guard.as_ref() else {
            return Ok(None);
        };
        conn.query_row(
            "SELECT target_path, repo_url, group_name, relative_path, file_hash, updated_at, backup_path
             FROM installed_files WHERE target_path = ?1;",
            params![target_path],
            map_installed_row,
        )
        .optional()
        .map_err(StateError::from)
    }

    pub fn list_installed_files(
        &self,
        repo_url: Option<&str>,
    ) -> Result<Vec<InstalledFileRecord>, StateError> {
        let guard = self.open_existing_conn()?;
        let Some(conn) = guard.as_ref() else {
            return Ok(Vec::new());
        };
        let (sql, filter): (&str, Vec<&str>) = match repo_url {
            Some(url) => (
                "SELECT target_path, repo_url, group_name, relative_path, file_hash, updated_at, backup_path
                 FROM installed_files WHERE repo_url = ?1 ORDER BY target_path ASC;",
                vec![url],
            ),
            None => (
                "SELECT target_path, repo_url, group_name, relative_path, file_hash, updated_at, backup_path
                 FROM installed_files ORDER BY target_path ASC;",
                Vec::new(),
            ),
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(filter), map_installed_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StateError::from)
    }

    pub fn remove_installed_file(
        &self,
        target_path: &str,
    ) -> Result<Option<InstalledFileRecord>, StateError> {
        let existing = self.get_installed_file(target_path)?;
        if existing.is_some()
            && let Some(conn) = self.open_existing_conn()?.as_ref()
        {
            conn.execute(
                "DELETE FROM installed_files WHERE target_path = ?1;",
                params![target_path],
            )?;
        }
        Ok(existing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn synced_rec(target: &str, repo: &str, group: &str, rel: &str, hash: &str) -> SyncedFileRecord {
        SyncedFileRecord {
            target_path: target.to_string(),
            repo_label: repo.to_string(),
            group_name: group.to_string(),
            relative_path: rel.to_string(),
            file_hash: hash.to_string(),
            updated_at: 1700000000,
        }
    }

    fn installed_rec(
        target: &str,
        url: &str,
        group: &str,
        rel: &str,
        hash: &str,
        backup: Option<&str>,
    ) -> InstalledFileRecord {
        InstalledFileRecord {
            target_path: target.to_string(),
            repo_url: url.to_string(),
            group_name: group.to_string(),
            relative_path: rel.to_string(),
            file_hash: hash.to_string(),
            updated_at: 1700000000,
            backup_path: backup.map(str::to_string),
        }
    }

    #[test]
    fn test_state_db_initialization_schema_and_pragmas() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("state.db");
        let db = StateDb::open(&db_path).expect("open should succeed");
        assert!(!db_path.exists());
        assert!(db.list_synced_files(None).expect("list empty").is_empty());
        assert!(!db_path.exists());

        let record = synced_rec(
            "/home/user/.zshrc",
            "main",
            "zsh",
            ".zshrc",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        db.upsert_synced_file(&record).expect("upsert");
        assert!(db_path.exists());

        {
            let guard = db.conn.lock().unwrap();
            let conn = guard.as_ref().expect("connection initialized");
            let mode: String = conn.query_row("PRAGMA journal_mode;", [], |r| r.get(0)).unwrap();
            assert_eq!(mode.to_uppercase(), "WAL");
            let user_version: u32 = conn.query_row("PRAGMA user_version;", [], |r| r.get(0)).unwrap();
            assert_eq!(user_version, STATE_DB_SCHEMA_VERSION);
        }
        assert_eq!(db.schema_version().expect("schema_version"), STATE_DB_SCHEMA_VERSION);
    }

    #[test]
    fn test_state_db_upgrades_legacy_zero_version_and_preserves_records() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("state.db");
        {
            let raw = Connection::open(&db_path).expect("open raw sqlite");
            raw.execute_batch(
                "CREATE TABLE synced_files (
                    target_path TEXT PRIMARY KEY NOT NULL, repo_label TEXT NOT NULL,
                    group_name TEXT NOT NULL, relative_path TEXT NOT NULL,
                    file_hash TEXT NOT NULL, updated_at INTEGER NOT NULL
                );
                INSERT INTO synced_files VALUES ('/home/user/.gitconfig', 'main', 'git', '.gitconfig', 'legacy_hash', 1700000000);
                PRAGMA user_version = 0;",
            ).expect("seed legacy v0 db");
        }
        let db = StateDb::open(&db_path).expect("open legacy v0 db");
        assert_eq!(db.schema_version().expect("schema_version"), STATE_DB_SCHEMA_VERSION);
        assert_eq!(db.get_synced_file("/home/user/.gitconfig").unwrap().unwrap().file_hash, "legacy_hash");
    }

    #[test]
    fn test_state_db_rejects_future_unsupported_schema_version() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("state.db");
        Connection::open(&db_path).unwrap().execute_batch("PRAGMA user_version = 2;").unwrap();
        let err = match StateDb::open(&db_path) {
            Err(e) => e,
            Ok(_) => panic!("opening state.db with future user_version must fail"),
        };
        assert!(matches!(
            err,
            StateError::UnsupportedSchemaVersion { found: 2, max_supported }
                if max_supported == STATE_DB_SCHEMA_VERSION
        ));
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn test_state_db_open_error_propagation_on_invalid_target() {
        let dir = tempdir().expect("tempdir");
        assert!(matches!(StateDb::open(dir.path()), Err(StateError::Sqlite(_) | StateError::Io(_))));
    }

    #[test]
    fn test_synced_files_crud() {
        let dir = tempdir().expect("tempdir");
        let db = StateDb::open(&dir.path().join("state.db")).expect("open");
        let record = synced_rec(
            "/home/user/.config/nvim/init.lua",
            "main",
            "nvim",
            "init.lua",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        db.upsert_synced_file(&record).expect("upsert");
        assert_eq!(db.get_synced_file("/home/user/.config/nvim/init.lua").unwrap(), Some(record));
        assert_eq!(db.list_synced_files(Some("main")).unwrap().len(), 1);
        assert_eq!(db.list_synced_files(Some("other")).unwrap().len(), 0);
        assert!(db.remove_synced_file("/home/user/.config/nvim/init.lua").unwrap());
        assert!(db.get_synced_file("/home/user/.config/nvim/init.lua").unwrap().is_none());
    }

    #[test]
    fn test_installed_files_preserves_original_backup_path_on_reinstall() {
        let dir = tempdir().expect("tempdir");
        let db = StateDb::open(&dir.path().join("state.db")).expect("open");
        let backup = "/home/user/.config/dotler/backups/zshrc.bak";
        db.upsert_installed_file(&installed_rec(
            "/home/user/.zshrc", "https://github.com/example/dots.git", "zsh", ".zshrc", "hash_v1", Some(backup),
        )).expect("initial install");
        db.upsert_installed_file(&installed_rec(
            "/home/user/.zshrc", "https://github.com/example/dots.git", "zsh", ".zshrc", "hash_v2", None,
        )).expect("reinstall");
        let fetched = db.get_installed_file("/home/user/.zshrc").unwrap().unwrap();
        assert_eq!(fetched.file_hash, "hash_v2");
        assert_eq!(fetched.backup_path.as_deref(), Some(backup));
    }

    #[test]
    fn test_synced_and_installed_tables_are_isolated() {
        let dir = tempdir().expect("tempdir");
        let db = StateDb::open(&dir.path().join("state.db")).expect("open");
        db.upsert_synced_file(&synced_rec("/home/user/.bashrc", "personal", "bash", ".bashrc", "personal_hash")).unwrap();
        db.upsert_installed_file(&installed_rec(
            "/home/user/.bashrc",
            "https://github.com/community/dots.git",
            "bash",
            ".bashrc",
            "community_hash",
            Some("/home/user/.config/dotler/backups/bashrc.bak"),
        )).unwrap();
        assert_eq!(db.get_synced_file("/home/user/.bashrc").unwrap().unwrap().file_hash, "personal_hash");
        assert!(db.remove_installed_file("/home/user/.bashrc").unwrap().is_some());
        assert_eq!(db.get_synced_file("/home/user/.bashrc").unwrap().unwrap().file_hash, "personal_hash");
    }

    #[test]
    fn test_find_orphaned_synced_files() {
        let dir = tempdir().expect("tempdir");
        let db = StateDb::open(&dir.path().join("state.db")).expect("open");
        for (path, repo, rel, hash) in [
            ("/home/user/active.txt", "main", "active.txt", "h1"),
            ("/home/user/orphaned.txt", "main", "orphaned.txt", "h2"),
            ("/home/user/other_repo.txt", "other", "other_repo.txt", "h3"),
        ] {
            db.upsert_synced_file(&synced_rec(path, repo, "docs", rel, hash)).unwrap();
        }
        let orphaned = db.find_orphaned_synced_files("main", &["/home/user/active.txt".to_string()]).unwrap();
        assert_eq!(orphaned, vec!["/home/user/orphaned.txt".to_string()]);
    }
}

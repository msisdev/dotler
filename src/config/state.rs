use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, params};

use crate::config::{LockError, StateError};

pub const STATE_DB_PATH: &str = "~/.config/dotler/state.db";
pub const DOTLER_LOCK_PATH: &str = "~/.config/dotler/dotler.lock";
pub const BACKUPS_DIR_PATH: &str = "~/.config/dotler/backups";
pub const SQLITE_JOURNAL_MODE: &str = "WAL";
pub const SQLITE_SYNCHRONOUS: &str = "NORMAL";
pub const SQLITE_BUSY_TIMEOUT_MS: u64 = 5000;
pub const DOTLER_LOCK_TIMEOUT_MS: u64 = 5000;
pub const DOTLER_LOCK_POLL_INTERVAL_MS: u64 = 50;
pub const TMP_FILE_PREFIX: &str = ".dotler-tmp-";
pub const ATOMIC_REPLACE_RETRIES: usize = 3;

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
    conn: Mutex<Connection>,
    db_path: PathBuf,
}

impl StateDb {
    pub fn open(path: &Path) -> Result<Self, StateError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;

        conn.execute_batch(&format!(
            "PRAGMA journal_mode = {SQLITE_JOURNAL_MODE};\n\
             PRAGMA synchronous = {SQLITE_SYNCHRONOUS};\n\
             PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS};"
        ))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS synced_files (
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
            CREATE INDEX IF NOT EXISTS idx_installed_files_group ON installed_files (repo_url, group_name);",
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
            db_path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.db_path
    }

    pub fn upsert_synced_file(&self, record: &SyncedFileRecord) -> Result<(), StateError> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT target_path, repo_label, group_name, relative_path, file_hash, updated_at
             FROM synced_files WHERE target_path = ?1;",
        )?;

        let record = stmt
            .query_row(params![target_path], |row| {
                Ok(SyncedFileRecord {
                    target_path: row.get(0)?,
                    repo_label: row.get(1)?,
                    group_name: row.get(2)?,
                    relative_path: row.get(3)?,
                    file_hash: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            })
            .optional()?;

        Ok(record)
    }

    pub fn list_synced_files(
        &self,
        repo_label: Option<&str>,
    ) -> Result<Vec<SyncedFileRecord>, StateError> {
        let conn = self.conn.lock().unwrap();
        let mut records = Vec::new();

        if let Some(label) = repo_label {
            let mut stmt = conn.prepare(
                "SELECT target_path, repo_label, group_name, relative_path, file_hash, updated_at
                 FROM synced_files WHERE repo_label = ?1 ORDER BY target_path ASC;",
            )?;
            let rows = stmt.query_map(params![label], |row| {
                Ok(SyncedFileRecord {
                    target_path: row.get(0)?,
                    repo_label: row.get(1)?,
                    group_name: row.get(2)?,
                    relative_path: row.get(3)?,
                    file_hash: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            })?;

            for row in rows {
                records.push(row?);
            }
        } else {
            let mut stmt = conn.prepare(
                "SELECT target_path, repo_label, group_name, relative_path, file_hash, updated_at
                 FROM synced_files ORDER BY target_path ASC;",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(SyncedFileRecord {
                    target_path: row.get(0)?,
                    repo_label: row.get(1)?,
                    group_name: row.get(2)?,
                    relative_path: row.get(3)?,
                    file_hash: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            })?;

            for row in rows {
                records.push(row?);
            }
        }

        Ok(records)
    }

    pub fn remove_synced_file(&self, target_path: &str) -> Result<bool, StateError> {
        let conn = self.conn.lock().unwrap();
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

        let orphaned = records
            .into_iter()
            .map(|r| r.target_path)
            .filter(|p| !active_set.contains(p.as_str()))
            .collect();

        Ok(orphaned)
    }

    pub fn upsert_installed_file(&self, record: &InstalledFileRecord) -> Result<(), StateError> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT target_path, repo_url, group_name, relative_path, file_hash, updated_at, backup_path
             FROM installed_files WHERE target_path = ?1;",
        )?;

        let record = stmt
            .query_row(params![target_path], |row| {
                Ok(InstalledFileRecord {
                    target_path: row.get(0)?,
                    repo_url: row.get(1)?,
                    group_name: row.get(2)?,
                    relative_path: row.get(3)?,
                    file_hash: row.get(4)?,
                    updated_at: row.get(5)?,
                    backup_path: row.get(6)?,
                })
            })
            .optional()?;

        Ok(record)
    }

    pub fn list_installed_files(
        &self,
        repo_url: Option<&str>,
    ) -> Result<Vec<InstalledFileRecord>, StateError> {
        let conn = self.conn.lock().unwrap();
        let mut records = Vec::new();

        if let Some(url) = repo_url {
            let mut stmt = conn.prepare(
                "SELECT target_path, repo_url, group_name, relative_path, file_hash, updated_at, backup_path
                 FROM installed_files WHERE repo_url = ?1 ORDER BY target_path ASC;",
            )?;
            let rows = stmt.query_map(params![url], |row| {
                Ok(InstalledFileRecord {
                    target_path: row.get(0)?,
                    repo_url: row.get(1)?,
                    group_name: row.get(2)?,
                    relative_path: row.get(3)?,
                    file_hash: row.get(4)?,
                    updated_at: row.get(5)?,
                    backup_path: row.get(6)?,
                })
            })?;

            for row in rows {
                records.push(row?);
            }
        } else {
            let mut stmt = conn.prepare(
                "SELECT target_path, repo_url, group_name, relative_path, file_hash, updated_at, backup_path
                 FROM installed_files ORDER BY target_path ASC;",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(InstalledFileRecord {
                    target_path: row.get(0)?,
                    repo_url: row.get(1)?,
                    group_name: row.get(2)?,
                    relative_path: row.get(3)?,
                    file_hash: row.get(4)?,
                    updated_at: row.get(5)?,
                    backup_path: row.get(6)?,
                })
            })?;

            for row in rows {
                records.push(row?);
            }
        }

        Ok(records)
    }

    pub fn remove_installed_file(
        &self,
        target_path: &str,
    ) -> Result<Option<InstalledFileRecord>, StateError> {
        let existing = self.get_installed_file(target_path)?;
        if existing.is_some() {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM installed_files WHERE target_path = ?1;",
                params![target_path],
            )?;
        }
        Ok(existing)
    }
}

pub struct DotlerLock {
    pub lock_path: PathBuf,
}

impl DotlerLock {
    pub fn new(lock_path: PathBuf) -> Self {
        Self { lock_path }
    }

    pub fn acquire(
        &self,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<DotlerLockGuard, LockError> {
        if let Some(parent) = self.lock_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock_path)?;

        let start = Instant::now();

        loop {
            match file.try_lock() {
                Ok(()) => return Ok(DotlerLockGuard { file }),
                Err(std::fs::TryLockError::WouldBlock) => {
                    if start.elapsed() >= timeout {
                        return Err(LockError::Timeout {
                            timeout_ms: timeout.as_millis() as u64,
                        });
                    }
                    std::thread::sleep(poll_interval);
                }
                Err(std::fs::TryLockError::Error(e)) => return Err(LockError::Io(e)),
            }
        }
    }
}

#[derive(Debug)]
pub struct DotlerLockGuard {
    #[allow(dead_code)]
    file: File,
}

impl Drop for DotlerLockGuard {
    fn drop(&mut self) {
        // No-Unlink on Unlock invariant:
        // Lock file is never removed from disk. Closing the file descriptor
        // upon Drop releases the kernel lock cleanly while preventing ghost inode race conditions.
    }
}

/// Writes `content` to `dest` atomically by creating a `.dotler-tmp-*` file
/// in the same parent directory, syncing to disk (`fsync`), preserving permissions
/// when replacing an existing file, and renaming into place with bounded retries.
pub fn atomic_write_file(dest: &Path, content: &[u8]) -> Result<(), StateError> {
    let parent = match dest.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    fs::create_dir_all(parent)?;

    let rand_id: u64 = rand::random();
    let tmp_path = parent.join(format!("{TMP_FILE_PREFIX}{rand_id:016x}"));

    {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)?;
        if let Err(e) = file.write_all(content).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&tmp_path);
            return Err(StateError::Io(e));
        }
    }

    #[cfg(unix)]
    if let Ok(metadata) = fs::metadata(dest) {
        let _ = fs::set_permissions(&tmp_path, metadata.permissions());
    }

    let mut attempts = 0;
    loop {
        match fs::rename(&tmp_path, dest) {
            Ok(()) => break,
            Err(e) => {
                attempts += 1;
                if attempts >= ATOMIC_REPLACE_RETRIES {
                    let _ = fs::remove_file(&tmp_path);
                    return Err(StateError::AtomicReplaceFailed(format!(
                        "Failed to rename {} to {}: {}",
                        tmp_path.display(),
                        dest.display(),
                        e
                    )));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_state_db_initialization_schema_and_pragmas() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("state.db");

        let db = StateDb::open(&db_path).expect("open should succeed");
        assert!(db_path.exists());

        // Verify journal mode is WAL
        let conn = db.conn.lock().unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
            .expect("pragma journal_mode");
        assert_eq!(mode.to_uppercase(), "WAL");
    }

    #[test]
    fn test_state_db_open_error_propagation_on_invalid_target() {
        let dir = tempdir().expect("tempdir");
        match StateDb::open(dir.path()) {
            Err(err) => assert!(matches!(err, StateError::Sqlite(_) | StateError::Io(_))),
            Ok(_) => panic!("opening directory as state.db must fail"),
        }
    }

    #[test]
    fn test_synced_files_crud() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("state.db");
        let db = StateDb::open(&db_path).expect("open");

        let record = SyncedFileRecord {
            target_path: "/home/user/.config/nvim/init.lua".to_string(),
            repo_label: "main".to_string(),
            group_name: "nvim".to_string(),
            relative_path: "init.lua".to_string(),
            file_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            updated_at: 1700000000,
        };

        db.upsert_synced_file(&record).expect("upsert");

        let fetched = db
            .get_synced_file("/home/user/.config/nvim/init.lua")
            .expect("get")
            .expect("should exist");
        assert_eq!(fetched, record);

        let list = db.list_synced_files(Some("main")).expect("list");
        assert_eq!(list.len(), 1);

        let list_other = db.list_synced_files(Some("other")).expect("list");
        assert_eq!(list_other.len(), 0);

        let removed = db
            .remove_synced_file("/home/user/.config/nvim/init.lua")
            .expect("remove");
        assert!(removed);

        let missing = db
            .get_synced_file("/home/user/.config/nvim/init.lua")
            .expect("get");
        assert!(missing.is_none());
    }

    #[test]
    fn test_installed_files_preserves_original_backup_path_on_reinstall() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("state.db");
        let db = StateDb::open(&db_path).expect("open");

        let initial_record = InstalledFileRecord {
            target_path: "/home/user/.zshrc".to_string(),
            repo_url: "https://github.com/example/dots.git".to_string(),
            group_name: "zsh".to_string(),
            relative_path: ".zshrc".to_string(),
            file_hash: "hash_v1".to_string(),
            updated_at: 1700000000,
            backup_path: Some("/home/user/.config/dotler/backups/zshrc.bak".to_string()),
        };

        db.upsert_installed_file(&initial_record)
            .expect("initial install");

        // Reinstall with a new hash, but None for backup_path
        let reinstall_record = InstalledFileRecord {
            target_path: "/home/user/.zshrc".to_string(),
            repo_url: "https://github.com/example/dots.git".to_string(),
            group_name: "zsh".to_string(),
            relative_path: ".zshrc".to_string(),
            file_hash: "hash_v2".to_string(),
            updated_at: 1700000500,
            backup_path: None,
        };

        db.upsert_installed_file(&reinstall_record)
            .expect("reinstall");

        let fetched = db
            .get_installed_file("/home/user/.zshrc")
            .expect("get")
            .expect("exists");
        assert_eq!(fetched.file_hash, "hash_v2");
        assert_eq!(
            fetched.backup_path,
            Some("/home/user/.config/dotler/backups/zshrc.bak".to_string()),
            "original backup_path must be preserved on reinstallation"
        );
    }

    #[test]
    fn test_synced_and_installed_tables_are_isolated() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("state.db");
        let db = StateDb::open(&db_path).expect("open");

        let synced_record = SyncedFileRecord {
            target_path: "/home/user/.bashrc".to_string(),
            repo_label: "personal".to_string(),
            group_name: "bash".to_string(),
            relative_path: ".bashrc".to_string(),
            file_hash: "personal_hash".to_string(),
            updated_at: 1700000000,
        };
        db.upsert_synced_file(&synced_record)
            .expect("upsert synced");

        let installed_record = InstalledFileRecord {
            target_path: "/home/user/.bashrc".to_string(),
            repo_url: "https://github.com/community/dots.git".to_string(),
            group_name: "bash".to_string(),
            relative_path: ".bashrc".to_string(),
            file_hash: "community_hash".to_string(),
            updated_at: 1700000100,
            backup_path: Some("/home/user/.config/dotler/backups/bashrc.bak".to_string()),
        };
        db.upsert_installed_file(&installed_record)
            .expect("upsert installed");

        // Verify synced file still intact
        let synced = db
            .get_synced_file("/home/user/.bashrc")
            .expect("get synced")
            .expect("synced must exist");
        assert_eq!(synced.file_hash, "personal_hash");

        // Remove installed file and verify synced record is unaffected
        let removed = db
            .remove_installed_file("/home/user/.bashrc")
            .expect("remove");
        assert!(removed.is_some());

        let synced_after = db
            .get_synced_file("/home/user/.bashrc")
            .expect("get synced")
            .expect("synced must still exist");
        assert_eq!(synced_after.file_hash, "personal_hash");
    }

    #[test]
    fn test_find_orphaned_synced_files() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("state.db");
        let db = StateDb::open(&db_path).expect("open");

        db.upsert_synced_file(&SyncedFileRecord {
            target_path: "/home/user/active.txt".to_string(),
            repo_label: "main".to_string(),
            group_name: "docs".to_string(),
            relative_path: "active.txt".to_string(),
            file_hash: "h1".to_string(),
            updated_at: 100,
        })
        .expect("upsert");

        db.upsert_synced_file(&SyncedFileRecord {
            target_path: "/home/user/orphaned.txt".to_string(),
            repo_label: "main".to_string(),
            group_name: "docs".to_string(),
            relative_path: "orphaned.txt".to_string(),
            file_hash: "h2".to_string(),
            updated_at: 100,
        })
        .expect("upsert");

        db.upsert_synced_file(&SyncedFileRecord {
            target_path: "/home/user/other_repo.txt".to_string(),
            repo_label: "other".to_string(),
            group_name: "docs".to_string(),
            relative_path: "other_repo.txt".to_string(),
            file_hash: "h3".to_string(),
            updated_at: 100,
        })
        .expect("upsert");

        let active = vec!["/home/user/active.txt".to_string()];
        let orphaned = db
            .find_orphaned_synced_files("main", &active)
            .expect("orphaned query");
        assert_eq!(orphaned, vec!["/home/user/orphaned.txt".to_string()]);
    }

    #[test]
    fn test_dotler_lock_acquire_and_drop_no_unlink() {
        let dir = tempdir().expect("tempdir");
        let lock_path = dir.path().join("dotler.lock");
        let lock = DotlerLock::new(lock_path.clone());

        {
            let _guard = lock
                .acquire(Duration::from_millis(500), Duration::from_millis(10))
                .expect("lock acquire");
            assert!(lock_path.exists());
        }

        // Invariant: No-Unlink on Unlock
        assert!(
            lock_path.exists(),
            "dotler.lock must remain on disk after unlock"
        );

        // Immediate re-acquire must succeed
        let guard2 = lock
            .acquire(Duration::from_millis(500), Duration::from_millis(10))
            .expect("re-acquire");
        drop(guard2);
        assert!(lock_path.exists());
    }

    #[test]
    fn test_dotler_lock_timeout_on_contention() {
        let dir = tempdir().expect("tempdir");
        let lock_path = dir.path().join("dotler.lock");
        let lock1 = DotlerLock::new(lock_path.clone());
        let lock2 = DotlerLock::new(lock_path.clone());

        let _guard = lock1
            .acquire(Duration::from_millis(1000), Duration::from_millis(10))
            .expect("lock1 acquire");

        // Attempting to acquire lock2 with short timeout should fail with Timeout
        let err = lock2
            .acquire(Duration::from_millis(150), Duration::from_millis(20))
            .expect_err("contention must time out");

        match err {
            LockError::Timeout { timeout_ms } => {
                assert!(timeout_ms >= 150);
            }
            other => panic!("expected LockError::Timeout, got {other:?}"),
        }
    }

    #[test]
    fn test_shared_atomic_write_file_creates_overwrites_and_preserves_permissions() {
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("nested").join("config.toml");

        atomic_write_file(&target, b"first = 1\n").expect("initial atomic write");
        assert_eq!(fs::read_to_string(&target).unwrap(), "first = 1\n");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        }

        atomic_write_file(&target, b"second = 2\n").expect("overwrite atomic write");
        assert_eq!(fs::read_to_string(&target).unwrap(), "second = 2\n");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "existing file permissions must be preserved");
        }

        let parent = target.parent().unwrap();
        let leftovers: Vec<_> = fs::read_dir(parent)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(TMP_FILE_PREFIX))
            .collect();
        assert!(
            leftovers.is_empty(),
            "atomic_write_file must leave zero temporary staging files"
        );
    }
}

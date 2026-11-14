use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::config::{LockError, StateError};

pub const DOTLER_LOCK_PATH: &str = "~/.config/dotler/dotler.lock";
pub const DOTLER_LOCK_TIMEOUT_MS: u64 = 5000;
pub const DOTLER_LOCK_POLL_INTERVAL_MS: u64 = 50;
pub const TMP_FILE_PREFIX: &str = ".dotler-tmp-";
pub const ATOMIC_REPLACE_RETRIES: usize = 3;

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

/// Creates a lazy [`Resource`] for `~/.config/dotler/dotler.lock`.
///
/// - `.get()` acquires an exclusive kernel file lock with a 5000ms timeout and 50ms poll interval on first access.
/// - `.set()` is a no-op since [`DotlerLockGuard`] releases its lock automatically on [`Drop`].
pub fn get_lock(lock_path: PathBuf) -> crate::config::Resource<DotlerLockGuard, LockError> {
    crate::config::Resource::new(
        move || {
            DotlerLock::new(lock_path.clone()).acquire(
                Duration::from_millis(DOTLER_LOCK_TIMEOUT_MS),
                Duration::from_millis(DOTLER_LOCK_POLL_INTERVAL_MS),
            )
        },
        |_guard| Ok(()),
    )
}

/// Writes `content` to `dest` atomically by creating a `.dotler-tmp-*` file
/// in the same parent directory, syncing to disk (`fsync`), preserving permissions
/// when replacing an existing file, and renaming into place with bounded retries.
pub fn write_file_safe(dest: &Path, content: &[u8]) -> Result<(), StateError> {
    let parent = match dest.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    fs::create_dir_all(parent)?;

    let rand_id: u64 = crate::crypto::random_u64();
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
    fn test_shared_write_file_safe_creates_overwrites_and_preserves_permissions() {
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("nested").join("config.toml");

        write_file_safe(&target, b"first = 1\n").expect("initial atomic write");
        assert_eq!(fs::read_to_string(&target).unwrap(), "first = 1\n");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        }

        write_file_safe(&target, b"second = 2\n").expect("overwrite atomic write");
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
            "write_file_safe must leave zero temporary staging files"
        );
    }
}

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use dotler::config::LockError;
use dotler::config::state::{
    DOTLER_LOCK_POLL_INTERVAL_MS, DOTLER_LOCK_TIMEOUT_MS, DotlerLock, InstalledFileRecord, StateDb,
    SyncedFileRecord,
};
use rusqlite::Connection;
use tempfile::tempdir;

fn test_binary_path() -> PathBuf {
    std::env::current_exe().expect("current test binary path")
}

// Subprocess entry points dispatched via command line arguments
#[test]
fn helper_lock_holder_process() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--role-lock-holder") {
        let lock_path = PathBuf::from(&args[pos + 1]);
        let ready_path = PathBuf::from(&args[pos + 2]);
        let hold_ms: u64 = args[pos + 3].parse().expect("hold_ms parse");

        let lock = DotlerLock::new(lock_path);
        let guard = lock
            .acquire(Duration::from_millis(5000), Duration::from_millis(50))
            .expect("child lock acquire failed");

        // Write ready marker file to signal parent
        fs::write(&ready_path, b"READY").expect("write ready file");

        thread::sleep(Duration::from_millis(hold_ms));
        drop(guard);
        std::process::exit(0);
    }
}

#[test]
fn helper_sqlite_writer_process() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--role-sqlite-writer") {
        let db_path = PathBuf::from(&args[pos + 1]);
        let ready_path = PathBuf::from(&args[pos + 2]);
        let iterations: usize = args[pos + 3].parse().expect("iterations parse");

        let db = StateDb::open(&db_path).expect("open db in child");
        fs::write(&ready_path, b"READY").expect("write ready file");

        for i in 0..iterations {
            let record = SyncedFileRecord {
                target_path: format!("/home/user/.config/file_{i}.txt"),
                repo_label: "main".to_string(),
                group_name: "test".to_string(),
                relative_path: format!("file_{i}.txt"),
                file_hash: format!("hash_{i:064x}"),
                updated_at: 1700000000 + i as i64,
            };
            if let Err(e) = db.upsert_synced_file(&record) {
                eprintln!("Child upsert failed at iteration {i}: {e:?}");
            }
            thread::sleep(Duration::from_millis(1));
        }

        std::process::exit(0);
    }
}

fn wait_for_marker(marker_path: &PathBuf, timeout: Duration) {
    let start = Instant::now();
    while !marker_path.exists() {
        if start.elapsed() >= timeout {
            panic!("Timed out waiting for marker file: {:?}", marker_path);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

// EMPIRICAL TEST 1: Two processes competing for dotler.lock: lock contention, timeout after 5000ms.
#[test]
fn test_empirical_lock_contention_and_5000ms_timeout() {
    let dir = tempdir().expect("tempdir");
    let lock_path = dir.path().join("dotler.lock");
    let ready_path = dir.path().join("ready.marker");

    // Spawn Process A holding the lock for 7000ms (> 5000ms timeout)
    let mut child_a = Command::new(test_binary_path())
        .arg("helper_lock_holder_process")
        .arg("--exact")
        .arg("--nocapture")
        .arg("--")
        .arg("--role-lock-holder")
        .arg(lock_path.to_str().unwrap())
        .arg(ready_path.to_str().unwrap())
        .arg("7000")
        .spawn()
        .expect("spawn child A");

    // Wait for Process A to confirm it holds the lock
    wait_for_marker(&ready_path, Duration::from_secs(5));

    // Process B (the current test thread) now attempts to acquire with 5000ms timeout
    let lock_b = DotlerLock::new(lock_path.clone());
    let start = Instant::now();
    let result = lock_b.acquire(
        Duration::from_millis(DOTLER_LOCK_TIMEOUT_MS),
        Duration::from_millis(DOTLER_LOCK_POLL_INTERVAL_MS),
    );
    let elapsed = start.elapsed();

    println!(
        "Process B contention result: {:?}, elapsed: {:?}",
        result.as_ref().map(|_| "Ok"),
        elapsed
    );

    match result {
        Err(LockError::Timeout { timeout_ms }) => {
            assert_eq!(timeout_ms, 5000, "Timeout parameter must be 5000ms");
            assert!(
                elapsed >= Duration::from_millis(4950),
                "Process B must wait at least 5000ms (elapsed: {elapsed:?})"
            );
            assert!(
                elapsed < Duration::from_millis(6000),
                "Process B must not hang indefinitely (elapsed: {elapsed:?})"
            );
            assert_eq!(
                LockError::Timeout { timeout_ms }.exit_code(),
                4,
                "Lock timeout exit code must be 4"
            );
        }
        Ok(_) => {
            panic!("Process B should NOT have acquired the lock while Process A was holding it")
        }
        Err(e) => panic!("Expected LockError::Timeout, got unexpected error: {e:?}"),
    }

    // Clean up child process
    let _ = child_a.wait();
}

// EMPIRICAL TEST 1B: Process B waits for Process A, and acquires lock when Process A releases it
#[test]
fn test_empirical_lock_handoff_between_processes() {
    let dir = tempdir().expect("tempdir");
    let lock_path = dir.path().join("dotler.lock");
    let ready_path = dir.path().join("ready.marker");

    // Spawn Process A holding lock for only 800ms
    let mut child_a = Command::new(test_binary_path())
        .arg("helper_lock_holder_process")
        .arg("--exact")
        .arg("--nocapture")
        .arg("--")
        .arg("--role-lock-holder")
        .arg(lock_path.to_str().unwrap())
        .arg(ready_path.to_str().unwrap())
        .arg("800")
        .spawn()
        .expect("spawn child A");

    wait_for_marker(&ready_path, Duration::from_secs(5));

    let lock_b = DotlerLock::new(lock_path.clone());
    let start = Instant::now();
    let guard_b = lock_b
        .acquire(Duration::from_millis(5000), Duration::from_millis(50))
        .expect("Process B must successfully acquire after Process A releases");
    let elapsed = start.elapsed();

    println!("Lock acquired by Process B after {:?}", elapsed);
    assert!(
        elapsed >= Duration::from_millis(700),
        "Process B waited for Process A release (elapsed: {elapsed:?})"
    );
    assert!(
        elapsed < Duration::from_millis(3000),
        "Process B acquired well before 5000ms timeout (elapsed: {elapsed:?})"
    );

    drop(guard_b);
    let _ = child_a.wait();
}

// EMPIRICAL TEST 1C: Multi-process stampede contention (5 processes competing)
#[test]
fn test_empirical_multi_process_stampede_mutual_exclusion() {
    let dir = tempdir().expect("tempdir");
    let lock_path = dir.path().join("dotler.lock");
    let counter_path = dir.path().join("counter.txt");
    fs::write(&counter_path, b"0").expect("init counter");

    let lock = Arc::new(DotlerLock::new(lock_path));
    let in_critical_section = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for _ in 0..5 {
        let lock_clone = Arc::clone(&lock);
        let in_cs = Arc::clone(&in_critical_section);
        let handle = thread::spawn(move || {
            for _ in 0..10 {
                let guard = lock_clone
                    .acquire(Duration::from_millis(5000), Duration::from_millis(20))
                    .expect("must acquire lock eventually");

                let prev = in_cs.fetch_add(1, Ordering::SeqCst);
                assert_eq!(
                    prev, 0,
                    "MUTUAL EXCLUSION VIOLATION: More than 1 thread inside critical section!"
                );

                thread::sleep(Duration::from_millis(10));

                let post = in_cs.fetch_sub(1, Ordering::SeqCst);
                assert_eq!(post, 1, "Counter corrupted in critical section");

                drop(guard);
                thread::sleep(Duration::from_millis(5));
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("thread join");
    }
}

// EMPIRICAL TEST 2: Dropping DotlerLockGuard releases kernel lock without deleting dotler.lock (No-Unlink on Unlock)
#[test]
fn test_empirical_no_unlink_on_unlock_and_reacquire() {
    let dir = tempdir().expect("tempdir");
    let lock_path = dir.path().join("dotler.lock");
    let lock = DotlerLock::new(lock_path.clone());

    // Phase 1: Acquire and verify file exists
    assert!(!lock_path.exists(), "Lock file should not exist initially");
    {
        let _guard1 = lock
            .acquire(Duration::from_millis(500), Duration::from_millis(10))
            .expect("first acquire");
        assert!(lock_path.exists(), "Lock file must exist while held");
    }

    // Phase 2: Invariant check - file MUST remain on disk after drop
    assert!(
        lock_path.exists(),
        "No-Unlink on Unlock invariant: dotler.lock must remain on disk after guard is dropped"
    );

    let metadata = fs::metadata(&lock_path).expect("lock metadata");
    assert_eq!(metadata.len(), 0, "dotler.lock must remain a 0-byte file");

    // Phase 3: Immediate re-acquire must succeed on existing file
    let guard2 = lock
        .acquire(Duration::from_millis(500), Duration::from_millis(10))
        .expect("second acquire on existing file");
    drop(guard2);

    assert!(
        lock_path.exists(),
        "dotler.lock must still exist after second unlock"
    );
}

// EMPIRICAL TEST 2B: Process crash (SIGKILL) while holding lock releases kernel lock and preserves file
#[test]
fn test_empirical_process_crash_releases_kernel_lock_and_preserves_file() {
    let dir = tempdir().expect("tempdir");
    let lock_path = dir.path().join("dotler.lock");
    let ready_path = dir.path().join("ready.marker");

    // Spawn child process holding lock for 30 seconds
    let mut child = Command::new(test_binary_path())
        .arg("helper_lock_holder_process")
        .arg("--exact")
        .arg("--nocapture")
        .arg("--")
        .arg("--role-lock-holder")
        .arg(lock_path.to_str().unwrap())
        .arg(ready_path.to_str().unwrap())
        .arg("30000")
        .spawn()
        .expect("spawn child");

    wait_for_marker(&ready_path, Duration::from_secs(5));
    assert!(lock_path.exists());

    // Abruptly kill child process with SIGKILL (kill -9)
    let pid = child.id();
    println!("Killing child process PID {} with SIGKILL...", pid);
    let kill_status = Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .status()
        .expect("kill -9 command");
    assert!(kill_status.success(), "SIGKILL must succeed");

    let _ = child.wait();

    // Invariant: dotler.lock must still exist on disk
    assert!(
        lock_path.exists(),
        "dotler.lock must remain on disk even after holding process is killed with SIGKILL"
    );

    // Invariant: Kernel lock must be automatically released by OS upon process death
    let lock_parent = DotlerLock::new(lock_path.clone());
    let start = Instant::now();
    let guard = lock_parent
        .acquire(Duration::from_millis(500), Duration::from_millis(10))
        .expect("Parent must immediately acquire lock after child process was SIGKILLed");
    let elapsed = start.elapsed();

    println!("Lock acquired after SIGKILL in {:?}", elapsed);
    assert!(
        elapsed < Duration::from_millis(100),
        "Kernel lock release upon SIGKILL must be instantaneous"
    );

    drop(guard);
    assert!(lock_path.exists());
}

// EMPIRICAL TEST 2C: Lock file containing arbitrary non-zero content is handled safely without truncation
#[test]
fn test_empirical_lock_preexisting_content_preserved_without_truncation() {
    let dir = tempdir().expect("tempdir");
    let lock_path = dir.path().join("dotler.lock");

    // Write pre-existing content to simulate external utility or metadata
    let test_content = b"pid=12345;timestamp=1700000000";
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&lock_path)
            .expect("create lock file with content");
        f.write_all(test_content).expect("write content");
    }

    let lock = DotlerLock::new(lock_path.clone());
    {
        let _guard = lock
            .acquire(Duration::from_millis(500), Duration::from_millis(10))
            .expect("acquire lock on non-empty file");

        // Verify content was NOT truncated while held
        let current_content = fs::read(&lock_path).expect("read content");
        assert_eq!(
            current_content, test_content,
            "truncate(false) must preserve existing file content"
        );
    }

    // Verify content is still preserved after release
    let post_content = fs::read(&lock_path).expect("read post content");
    assert_eq!(post_content, test_content);
}

// EMPIRICAL TEST 3: Concurrent SQLite operations under WAL mode survive without corruption
#[test]
fn test_empirical_sqlite_wal_concurrency_and_integrity() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("state.db");

    // Initialize StateDb and verify lazy Write-On-Demand before first write
    {
        let db = StateDb::open(&db_path).expect("open state db");
        assert_eq!(db.path(), db_path);
        assert!(
            !db_path.exists(),
            "state.db must not be created on disk until a write occurs"
        );
    }

    let db = Arc::new(StateDb::open(&db_path).expect("open shared db"));
    let mut handles = Vec::new();

    // Spawn 4 concurrent threads reading and writing simultaneously
    for thread_idx in 0..4 {
        let db_clone = Arc::clone(&db);
        let handle = thread::spawn(move || {
            for i in 0..100 {
                let target = format!("/home/user/.config/thread_{thread_idx}_file_{i}.txt");
                let record = SyncedFileRecord {
                    target_path: target.clone(),
                    repo_label: "main".to_string(),
                    group_name: format!("group_{thread_idx}"),
                    relative_path: format!("file_{i}.txt"),
                    file_hash: format!("hash_{thread_idx}_{i:064x}"),
                    updated_at: 1700000000 + (thread_idx * 1000 + i) as i64,
                };

                db_clone.upsert_synced_file(&record).expect("upsert synced");
                let fetched = db_clone
                    .get_synced_file(&target)
                    .expect("get synced")
                    .expect("must exist");
                assert_eq!(fetched.file_hash, record.file_hash);

                let installed = InstalledFileRecord {
                    target_path: format!("/home/user/inst_{thread_idx}_{i}.txt"),
                    repo_url: "https://example.com/repo.git".to_string(),
                    group_name: format!("group_{thread_idx}"),
                    relative_path: format!("inst_{i}.txt"),
                    file_hash: format!("hash_inst_{i}"),
                    updated_at: 1700000000,
                    backup_path: Some(format!("/backup/{thread_idx}_{i}.bak")),
                };
                db_clone
                    .upsert_installed_file(&installed)
                    .expect("upsert installed");
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("thread join");
    }

    // Verify database integrity and WAL mode using SQLite PRAGMA
    let raw_conn = Connection::open(&db_path).expect("open raw conn");
    let journal_mode: String = raw_conn
        .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
        .expect("query journal_mode");
    assert_eq!(
        journal_mode.to_uppercase(),
        "WAL",
        "Journal mode must be WAL"
    );
    let integrity: String = raw_conn
        .query_row("PRAGMA integrity_check;", [], |r| r.get(0))
        .expect("pragma integrity_check");
    assert_eq!(integrity, "ok", "Database integrity check must return 'ok'");

    let synced_count: i64 = raw_conn
        .query_row("SELECT COUNT(*) FROM synced_files;", [], |r| r.get(0))
        .expect("count synced");
    assert_eq!(
        synced_count, 400,
        "All 400 synced file records must be present"
    );

    let installed_count: i64 = raw_conn
        .query_row("SELECT COUNT(*) FROM installed_files;", [], |r| r.get(0))
        .expect("count installed");
    assert_eq!(
        installed_count, 400,
        "All 400 installed file records must be present"
    );
}

// EMPIRICAL TEST 3B: Abrupt process termination (SIGKILL) during active SQLite WAL writes
#[test]
fn test_empirical_sqlite_wal_abrupt_termination_survives_without_corruption() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("state.db");
    let ready_path = dir.path().join("ready.marker");

    // Initialize StateDb in WAL mode
    {
        let _db = StateDb::open(&db_path).expect("init db");
    }

    // Spawn a child process performing heavy writes
    let mut child = Command::new(test_binary_path())
        .arg("helper_sqlite_writer_process")
        .arg("--exact")
        .arg("--nocapture")
        .arg("--")
        .arg("--role-sqlite-writer")
        .arg(db_path.to_str().unwrap())
        .arg(ready_path.to_str().unwrap())
        .arg("5000") // 5000 iterations
        .spawn()
        .expect("spawn writer child");

    wait_for_marker(&ready_path, Duration::from_secs(5));

    // Let the child write for 80ms, then abruptly KILL it with SIGKILL (-9)
    thread::sleep(Duration::from_millis(80));

    let pid = child.id();
    println!(
        "Sending SIGKILL to SQLite writer PID {} mid-transaction...",
        pid
    );
    let kill_status = Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .status()
        .expect("kill -9");
    assert!(kill_status.success());

    let _ = child.wait();

    // Now open the database with a new connection and verify WAL recovery & integrity
    let raw_conn = Connection::open(&db_path).expect("open raw conn after SIGKILL");
    let integrity: String = raw_conn
        .query_row("PRAGMA integrity_check;", [], |r| r.get(0))
        .expect("integrity_check query");
    assert_eq!(
        integrity, "ok",
        "PRAGMA integrity_check must return 'ok' after abrupt SIGKILL in WAL mode"
    );

    // Verify StateDb can still read and write normally
    let db = StateDb::open(&db_path).expect("reopen StateDb");
    let list = db
        .list_synced_files(None)
        .expect("list synced files after recovery");
    println!("Recovered synced files count: {}", list.len());
    assert!(
        !list.is_empty(),
        "Some records should have been committed before SIGKILL"
    );

    // Perform a new write to confirm WAL recovery is complete and writable
    let new_record = SyncedFileRecord {
        target_path: "/home/user/post_recovery.txt".to_string(),
        repo_label: "main".to_string(),
        group_name: "test".to_string(),
        relative_path: "post_recovery.txt".to_string(),
        file_hash: "recovered_hash".to_string(),
        updated_at: 1700099999,
    };
    db.upsert_synced_file(&new_record)
        .expect("upsert after recovery");

    let fetched = db
        .get_synced_file("/home/user/post_recovery.txt")
        .expect("get")
        .expect("must exist");
    assert_eq!(fetched.file_hash, "recovered_hash");

    let post_integrity: String = raw_conn
        .query_row("PRAGMA integrity_check;", [], |r| r.get(0))
        .expect("second integrity_check");
    assert_eq!(post_integrity, "ok");
}

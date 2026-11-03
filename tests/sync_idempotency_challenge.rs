use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use dotler::config::repo::{OsInfo, RepoConfig, VaultConfig};
use dotler::config::state::{
    DotlerLock, DotlerLockGuard, InstalledFileRecord, StateDb, SyncedFileRecord, TMP_FILE_PREFIX,
};
use dotler::crypto::keyring::OsKeyring;
use dotler::crypto::vault::{EncryptedFile, VaultKey, init_vault};
use dotler::engine::{
    EngineError, FileSyncStatus, SyncEngine, TidyOrphanPolicy, atomic_write_file,
};
use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;

static TEST_KEYRING_LOCK: Mutex<()> = Mutex::new(());

struct TestKeyringGuard<'a> {
    _lock: std::sync::MutexGuard<'a, ()>,
}

impl<'a> TestKeyringGuard<'a> {
    fn new() -> Self {
        let lock = TEST_KEYRING_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        OsKeyring::enable_mock();
        OsKeyring::clear_mock();
        Self { _lock: lock }
    }
}

impl<'a> Drop for TestKeyringGuard<'a> {
    fn drop(&mut self) {
        OsKeyring::clear_mock();
        OsKeyring::disable_mock();
    }
}

#[allow(dead_code)]
struct ChallengeSandbox {
    _root: TempDir,
    home_dir: PathBuf,
    repo_dir: PathBuf,
    dotler_dir: PathBuf,
    state_db: StateDb,
    lock_path: PathBuf,
}

impl ChallengeSandbox {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("create challenge sandbox tempdir");
        let root_path = root.path();

        let home_dir = root_path.join("home");
        let repo_dir = root_path.join("dotfiles");
        let dotler_dir = home_dir.join(".config").join("dotler");

        fs::create_dir_all(&home_dir).unwrap();
        fs::create_dir_all(&repo_dir).unwrap();
        fs::create_dir_all(&dotler_dir).unwrap();

        let db_path = dotler_dir.join("state.db");
        let state_db = StateDb::open(&db_path).expect("open state.db");
        let lock_path = dotler_dir.join("dotler.lock");

        Self {
            _root: root,
            home_dir,
            repo_dir,
            dotler_dir,
            state_db,
            lock_path,
        }
    }

    fn acquire_lock(&self) -> DotlerLockGuard {
        let lock = DotlerLock::new(self.lock_path.clone());
        lock.acquire(Duration::from_millis(5000), Duration::from_millis(50))
            .expect("acquire challenge lock")
    }

    fn write_home_file(&self, rel_path: &str, content: &[u8]) -> PathBuf {
        let full_path = self.home_dir.join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&full_path, content).unwrap();
        full_path
    }

    fn write_repo_file(&self, rel_path: &str, content: &[u8]) -> PathBuf {
        let full_path = self.repo_dir.join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&full_path, content).unwrap();
        full_path
    }

    fn create_vault(&self, password: &str) -> (VaultConfig, VaultKey) {
        let secret = SecretString::new(password.to_string());
        let (config, key, _) = init_vault(&secret).unwrap();
        (config, key)
    }

    fn sync_engine<'a>(
        &'a self,
        repo_config: &'a RepoConfig,
        vault_key: Option<&'a VaultKey>,
    ) -> SyncEngine<'a> {
        SyncEngine::new(
            "default",
            &self.repo_dir,
            repo_config,
            &self.state_db,
            vec![],
            OsInfo::detect(),
            vault_key,
        )
        .with_home_dir(&self.home_dir)
    }
}

// ---------------------------------------------------------------------------
// 1. Hash-Match Idempotency & Repeated Export Verification
// ---------------------------------------------------------------------------

#[test]
fn test_export_idempotency_avoids_io_and_preserves_file_inode_and_mtime() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml_str = r#"
[shell]
os-linux = "~"
files = "shell/.bashrc"
"#;
    let config = RepoConfig::parse(toml_str).unwrap();

    let initial_content = b"export PATH=$PATH:/usr/local/bin\n";
    sandbox.write_repo_file("shell/shell/.bashrc", initial_content);

    let engine = sandbox.sync_engine(&config, None);

    // First export: file is created on OS
    let plans = engine.plan(None, &lock).unwrap();
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].status, FileSyncStatus::ModifiedInRepo);

    let report1 = engine.export_files(&plans, &lock, false, false).unwrap();
    assert_eq!(report1.processed, 1);
    assert_eq!(report1.skipped, 0);

    let target_path = sandbox.home_dir.join("shell/.bashrc");
    assert!(target_path.is_file());
    assert_eq!(fs::read(&target_path).unwrap(), initial_content);

    let meta_before = fs::metadata(&target_path).unwrap();
    #[cfg(unix)]
    let inode_before = meta_before.ino();
    let mtime_before = meta_before.modified().unwrap();

    // Sleep briefly to guarantee mtime resolution advance if touched
    std::thread::sleep(Duration::from_millis(60));

    // Execute 30 consecutive exports in a stress loop
    for iter in 1..=30 {
        let plans = engine.plan(None, &lock).unwrap();
        assert_eq!(plans.len(), 1);
        assert_eq!(
            plans[0].status,
            FileSyncStatus::Synced,
            "Failed at iteration {}",
            iter
        );

        let report = engine.export_files(&plans, &lock, false, false).unwrap();
        assert_eq!(
            report.skipped, 1,
            "Iteration {} should have skipped disk write",
            iter
        );
        assert_eq!(
            report.processed, 0,
            "Iteration {} must not process any writes",
            iter
        );

        let meta_after = fs::metadata(&target_path).unwrap();
        #[cfg(unix)]
        assert_eq!(
            meta_after.ino(),
            inode_before,
            "Iteration {} changed inode (unexpected disk write)",
            iter
        );
        assert_eq!(
            meta_after.modified().unwrap(),
            mtime_before,
            "Iteration {} updated mtime (unexpected disk write)",
            iter
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Hash-Based Re-Encryption Skipping in Import
// ---------------------------------------------------------------------------

#[test]
fn test_import_reencryption_skipping_guarantees_byte_exact_repo_ciphertext() {
    let _keyring = TestKeyringGuard::new();
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();
    let (vault_cfg, vault_key) = sandbox.create_vault("strong-passphrase-sync-test");

    let toml_str = format!(
        r#"
[vault]
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[secrets]
os-linux = "~"
files = "@credentials.env"
"#,
        vault_cfg.vault_id, vault_cfg.password_slot, vault_cfg.recovery_slot
    );
    let config = RepoConfig::parse(&toml_str).unwrap();

    let initial_secret = b"AWS_SECRET_ACCESS_KEY=ABCD1234EFGH5678\n";
    sandbox.write_home_file("credentials.env", initial_secret);

    let engine = sandbox.sync_engine(&config, Some(&vault_key));

    // First import: encrypts file and writes credentials.env.enc
    let plans = engine.plan(None, &lock).unwrap();
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].status, FileSyncStatus::ModifiedLocally);

    let report1 = engine.import_files(&plans, &lock, false).unwrap();
    assert_eq!(report1.processed, 1);
    assert_eq!(report1.skipped, 0);

    let enc_path = sandbox.repo_dir.join("secrets/credentials.env.enc");
    assert!(enc_path.is_file());
    let raw_enc_initial = fs::read(&enc_path).unwrap();

    // Verify plaintext matches after decryption
    let enc_file1 = EncryptedFile::from_bytes(&raw_enc_initial).unwrap();
    let plain1 = vault_key.decrypt_file(&enc_file1).unwrap();
    assert_eq!(plain1.expose_secret(), initial_secret);

    // Repeated imports with unchanged plaintext
    // Because XChaCha20 uses random nonces, re-encrypting WOULD alter raw bytes.
    // Hash-based re-encryption skipping guarantees byte-for-byte identity!
    for iter in 1..=10 {
        let plans = engine.plan(None, &lock).unwrap();
        assert_eq!(plans[0].status, FileSyncStatus::Synced);

        let report = engine.import_files(&plans, &lock, false).unwrap();
        assert_eq!(
            report.skipped, 1,
            "Iteration {} must skip re-encryption",
            iter
        );
        assert_eq!(
            report.processed, 0,
            "Iteration {} must not re-encrypt",
            iter
        );

        let raw_enc_current = fs::read(&enc_path).unwrap();
        assert_eq!(
            raw_enc_current, raw_enc_initial,
            "Iteration {} modified .enc bytes (re-encryption skipping failed!)",
            iter
        );
    }

    // Now modify the OS plaintext: re-encryption MUST trigger
    let updated_secret = b"AWS_SECRET_ACCESS_KEY=NEW_KEY_9999\n";
    sandbox.write_home_file("credentials.env", updated_secret);

    let plans = engine.plan(None, &lock).unwrap();
    assert_eq!(plans[0].status, FileSyncStatus::ModifiedLocally);

    let report_update = engine.import_files(&plans, &lock, false).unwrap();
    assert_eq!(report_update.processed, 1);
    assert_eq!(report_update.skipped, 0);

    let raw_enc_updated = fs::read(&enc_path).unwrap();
    assert_ne!(
        raw_enc_updated, raw_enc_initial,
        "Modified plaintext must generate new ciphertext"
    );

    let enc_file2 = EncryptedFile::from_bytes(&raw_enc_updated).unwrap();
    let plain2 = vault_key.decrypt_file(&enc_file2).unwrap();
    assert_eq!(plain2.expose_secret(), updated_secret);
}

#[test]
fn test_import_reencryption_skipping_db_hash_bypass_avoids_repo_decryption() {
    let _keyring = TestKeyringGuard::new();
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();
    let (vault_cfg, vault_key) = sandbox.create_vault("strong-passphrase-bypass-test");

    let toml_str = format!(
        r#"
[vault]
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[secrets]
os-linux = "~"
files = "@token.txt"
"#,
        vault_cfg.vault_id, vault_cfg.password_slot, vault_cfg.recovery_slot
    );
    let config = RepoConfig::parse(&toml_str).unwrap();

    let plain_content = b"static-bearer-token-val\n";
    let target_path = sandbox.write_home_file("token.txt", plain_content);
    let target_hash = blake3::hash(plain_content).to_hex().to_string();

    // Populate database record with the matching hash
    sandbox
        .state_db
        .upsert_synced_file(&SyncedFileRecord {
            target_path: target_path.to_string_lossy().to_string(),
            repo_label: "default".into(),
            group_name: "secrets".into(),
            relative_path: "token.txt".into(),
            file_hash: target_hash,
            updated_at: 1000,
        })
        .unwrap();

    // Intentionally corrupt the repository file with invalid garbage
    let enc_path = sandbox.write_repo_file("secrets/token.txt.enc", b"INVALID_GARBAGE_PAYLOAD");

    let engine = sandbox.sync_engine(&config, Some(&vault_key));
    let plans = engine.plan(None, &lock).unwrap();

    // Import should succeed by skipping re-encryption via DB hash match without decrypting garbage
    let report = engine.import_files(&plans, &lock, false).unwrap();
    assert_eq!(report.skipped, 1);
    assert_eq!(report.processed, 0);

    // Garbage file remains untouched
    assert_eq!(fs::read(&enc_path).unwrap(), b"INVALID_GARBAGE_PAYLOAD");
}

// ---------------------------------------------------------------------------
// 3. Conflict Guards & Atomic Rollbacks: Exit Code 1 vs --force
// ---------------------------------------------------------------------------

#[test]
fn test_export_conflict_guard_aborts_with_exit_code_1_and_preserves_local_edits() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml_str = r#"
[configs]
os-linux = "~"
files = "app/config.json"
"#;
    let config = RepoConfig::parse(toml_str).unwrap();

    // 1. Initial synced state: both OS and Repo have v1
    let content_v1 = b"{\"version\": 1}\n";
    let hash_v1 = blake3::hash(content_v1).to_hex().to_string();

    let target_path = sandbox.write_home_file("app/config.json", content_v1);
    sandbox.write_repo_file("configs/app/config.json", content_v1);

    sandbox
        .state_db
        .upsert_synced_file(&SyncedFileRecord {
            target_path: target_path.to_string_lossy().to_string(),
            repo_label: "default".into(),
            group_name: "configs".into(),
            relative_path: "app/config.json".into(),
            file_hash: hash_v1,
            updated_at: 100,
        })
        .unwrap();

    // 2. Adversarially modify OS locally (e.g. user edit)
    let local_edit = b"{\"version\": 1, \"user_local_change\": true}\n";
    sandbox.write_home_file("app/config.json", local_edit);

    // 3. Remote/repo is updated to v2
    let content_v2 = b"{\"version\": 2, \"upstream\": true}\n";
    sandbox.write_repo_file("configs/app/config.json", content_v2);

    let engine = sandbox.sync_engine(&config, None);
    let plans = engine.plan(None, &lock).unwrap();
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].status, FileSyncStatus::Conflict);

    // Export without --force MUST abort
    let err = engine
        .export_files(&plans, &lock, false, false)
        .expect_err("export without force must fail on conflict");

    match &err {
        EngineError::SyncConflict { path, reason } => {
            assert_eq!(path, &target_path);
            assert!(reason.contains("modified locally"));
        }
        other => panic!("Expected SyncConflict, got: {:?}", other),
    }

    // Verify exit code is strictly 1
    assert_eq!(
        err.exit_code(),
        1,
        "Local edit conflict must map to exit code 1"
    );
    assert_eq!(
        err.error_code(),
        "LOCAL_EDIT_CONFLICT",
        "Error code must be LOCAL_EDIT_CONFLICT"
    );

    // EMPIRICAL PROOF: target file on OS must remain 100% UNTOUCHED
    let os_after = fs::read(&target_path).unwrap();
    assert_eq!(
        os_after, local_edit,
        "Local edits must never be overwritten on conflict!"
    );

    // Now re-run with force: true
    let force_report = engine
        .export_files(&plans, &lock, true, false)
        .expect("export with force must succeed");
    assert_eq!(force_report.processed, 1);
    assert_eq!(force_report.skipped, 0);

    // OS file must now have upstream content v2
    let os_forced = fs::read(&target_path).unwrap();
    assert_eq!(os_forced, content_v2);

    // Database record must be updated to hash_v2
    let hash_v2 = blake3::hash(content_v2).to_hex().to_string();
    let db_record = sandbox
        .state_db
        .get_synced_file(&target_path.to_string_lossy())
        .unwrap()
        .expect("db record exists");
    assert_eq!(db_record.file_hash, hash_v2);
}

#[test]
fn test_export_conflict_in_multi_file_halts_prior_to_unrelated_writes() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml_str = r#"
[group_a]
os-linux = "~"
files = """
file_a.txt
file_b.txt
file_c.txt
"""
"#;
    let config = RepoConfig::parse(toml_str).unwrap();

    // file_a: already in sync
    sandbox.write_repo_file("group_a/file_a.txt", b"content_a");
    let target_a = sandbox.write_home_file("file_a.txt", b"content_a");
    sandbox
        .state_db
        .upsert_synced_file(&SyncedFileRecord {
            target_path: target_a.to_string_lossy().to_string(),
            repo_label: "default".into(),
            group_name: "group_a".into(),
            relative_path: "file_a.txt".into(),
            file_hash: blake3::hash(b"content_a").to_hex().to_string(),
            updated_at: 100,
        })
        .unwrap();

    // file_b: conflict (modified locally and in repo)
    sandbox.write_repo_file("group_a/file_b.txt", b"repo_b_v2");
    let target_b = sandbox.write_home_file("file_b.txt", b"local_b_edit");
    sandbox
        .state_db
        .upsert_synced_file(&SyncedFileRecord {
            target_path: target_b.to_string_lossy().to_string(),
            repo_label: "default".into(),
            group_name: "group_a".into(),
            relative_path: "file_b.txt".into(),
            file_hash: blake3::hash(b"b_v1").to_hex().to_string(),
            updated_at: 100,
        })
        .unwrap();

    // file_c: new in repo, missing locally
    sandbox.write_repo_file("group_a/file_c.txt", b"repo_c_new");
    let target_c = sandbox.home_dir.join("file_c.txt");

    let engine = sandbox.sync_engine(&config, None);
    let plans = engine.plan(None, &lock).unwrap();

    // Export without force: must abort at file_b
    let err = engine
        .export_files(&plans, &lock, false, false)
        .unwrap_err();
    assert_eq!(err.exit_code(), 1);

    // file_c must NOT have been created!
    assert!(
        !target_c.exists(),
        "file_c must not be written when export halts on prior conflict"
    );
    // file_b must still have local edits
    assert_eq!(fs::read(&target_b).unwrap(), b"local_b_edit");
}

// ---------------------------------------------------------------------------
// 4. Interruption Safety, Staging Isolation, & Unix Permissions
// ---------------------------------------------------------------------------

#[test]
fn test_atomic_write_file_same_directory_staging_and_clean_replacement() {
    let sandbox = ChallengeSandbox::new();
    let dest_file = sandbox.home_dir.join("subdir/nested/dest.txt");

    let initial = b"INITIAL_DATA";
    atomic_write_file(&dest_file, initial).expect("initial atomic write");
    assert_eq!(fs::read(&dest_file).unwrap(), initial);

    // Parent directory should not contain any remaining temporary files
    let parent = dest_file.parent().unwrap();
    let mut tmp_entries = Vec::new();
    for entry in fs::read_dir(parent).unwrap().filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(TMP_FILE_PREFIX) {
            tmp_entries.push(name);
        }
    }
    assert!(
        tmp_entries.is_empty(),
        "No temporary staging files should remain after successful write: {:?}",
        tmp_entries
    );

    // Overwrite atomically
    let updated = b"UPDATED_DATA_AFTER_ATOMIC_REPLACE";
    atomic_write_file(&dest_file, updated).expect("update atomic write");
    assert_eq!(fs::read(&dest_file).unwrap(), updated);
}

#[test]
#[cfg(unix)]
fn test_atomic_write_file_preserves_unix_permissions() {
    let sandbox = ChallengeSandbox::new();
    let exec_file = sandbox.home_dir.join("bin/script.sh");

    // Create target with executable permissions 0o755
    fs::create_dir_all(exec_file.parent().unwrap()).unwrap();
    fs::write(&exec_file, b"#!/bin/sh\necho 1\n").unwrap();
    fs::set_permissions(&exec_file, fs::Permissions::from_mode(0o755)).unwrap();

    let meta1 = fs::metadata(&exec_file).unwrap();
    assert_eq!(meta1.permissions().mode() & 0o777, 0o755);

    // Atomic replace
    atomic_write_file(&exec_file, b"#!/bin/sh\necho 2\n").unwrap();
    let meta2 = fs::metadata(&exec_file).unwrap();
    assert_eq!(
        meta2.permissions().mode() & 0o777,
        0o755,
        "Executable 0o755 permissions must be preserved across atomic writes"
    );

    // Create target with secret permissions 0o600
    let secret_file = sandbox.home_dir.join(".ssh/id_rsa");
    fs::create_dir_all(secret_file.parent().unwrap()).unwrap();
    fs::write(&secret_file, b"PRIVATE_KEY_DATA").unwrap();
    fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o600)).unwrap();

    atomic_write_file(&secret_file, b"NEW_KEY_DATA").unwrap();
    let meta3 = fs::metadata(&secret_file).unwrap();
    assert_eq!(
        meta3.permissions().mode() & 0o777,
        0o600,
        "Private 0o600 permissions must be preserved across atomic writes"
    );
}

#[test]
fn test_stale_dotler_tmp_files_completely_ignored_by_plan_and_tidy() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml_str = r#"
[tools]
os-linux = "~"
files = "valid.sh"
"#;
    let config = RepoConfig::parse(toml_str).unwrap();

    sandbox.write_repo_file("tools/valid.sh", b"echo valid\n");
    sandbox.write_home_file("valid.sh", b"echo valid\n");

    // Intentionally inject stale temporary files from simulated crashed processes
    let stale_tmp_repo =
        sandbox.write_repo_file("tools/.dotler-tmp-deadbeef12345678", b"STALE_LEFTOVER_REPO");
    let stale_tmp_home =
        sandbox.write_home_file(".dotler-tmp-cafebabe87654321", b"STALE_LEFTOVER_HOME");

    let engine = sandbox.sync_engine(&config, None);

    // 1. Plan must ignore stale tmp files
    let plans = engine.plan(None, &lock).unwrap();
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].relative_path, "valid.sh");

    // 2. Tidy must ignore stale tmp files
    let tidy_report = engine
        .tidy(None, &lock, TidyOrphanPolicy::PurgeFromOs, false)
        .unwrap();
    assert_eq!(tidy_report.removed_from_repo, 0);
    assert_eq!(tidy_report.removed_os_orphans.len(), 0);

    // Stale files were not touched
    assert!(stale_tmp_repo.is_file());
    assert!(stale_tmp_home.is_file());
}

// ---------------------------------------------------------------------------
// 5. Tidy Table Isolation: synced_files vs installed_files
// ---------------------------------------------------------------------------

#[test]
fn test_tidy_orphan_cleanup_modifies_synced_files_and_never_touches_installed_files() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml_str = r#"
[group1]
os-linux = "~"
files = "active.txt"
"#;
    let config = RepoConfig::parse(toml_str).unwrap();

    // 1. Setup active synced file
    let active_path = sandbox.write_home_file("active.txt", b"active-content");
    sandbox.write_repo_file("group1/active.txt", b"active-content");
    sandbox
        .state_db
        .upsert_synced_file(&SyncedFileRecord {
            target_path: active_path.to_string_lossy().to_string(),
            repo_label: "default".into(),
            group_name: "group1".into(),
            relative_path: "active.txt".into(),
            file_hash: blake3::hash(b"active-content").to_hex().to_string(),
            updated_at: 100,
        })
        .unwrap();

    // 2. Setup orphaned synced file (in DB and OS, but removed from repo/config)
    let orphan_path = sandbox.write_home_file("orphan.txt", b"orphan-content");
    let orphan_path_str = orphan_path.to_string_lossy().to_string();
    sandbox
        .state_db
        .upsert_synced_file(&SyncedFileRecord {
            target_path: orphan_path_str.clone(),
            repo_label: "default".into(),
            group_name: "group1".into(),
            relative_path: "orphan.txt".into(),
            file_hash: blake3::hash(b"orphan-content").to_hex().to_string(),
            updated_at: 100,
        })
        .unwrap();

    // 3. Setup multiple records in installed_files (from remote git packages)
    let installed_rec1 = InstalledFileRecord {
        target_path: sandbox
            .home_dir
            .join("remote/pkg1.cfg")
            .to_string_lossy()
            .to_string(),
        repo_url: "https://github.com/example/dotfiles.git".into(),
        group_name: "vim".into(),
        relative_path: "pkg1.cfg".into(),
        backup_path: Some("/tmp/backup/pkg1.cfg".into()),
        file_hash: "hash_pkg1".into(),
        updated_at: 200,
    };
    let installed_rec2 = InstalledFileRecord {
        target_path: sandbox
            .home_dir
            .join("remote/pkg2.cfg")
            .to_string_lossy()
            .to_string(),
        repo_url: "https://github.com/example/dotfiles.git".into(),
        group_name: "tmux".into(),
        relative_path: "pkg2.cfg".into(),
        backup_path: None,
        file_hash: "hash_pkg2".into(),
        updated_at: 201,
    };
    // Even an installed file whose path matches orphan_path
    let installed_rec3_collision = InstalledFileRecord {
        target_path: orphan_path_str.clone(),
        repo_url: "https://github.com/another/repo.git".into(),
        group_name: "shadow".into(),
        relative_path: "orphan.txt".into(),
        backup_path: Some("/tmp/backup/orphan.txt".into()),
        file_hash: "hash_orphan_installed".into(),
        updated_at: 202,
    };

    sandbox
        .state_db
        .upsert_installed_file(&installed_rec1)
        .unwrap();
    sandbox
        .state_db
        .upsert_installed_file(&installed_rec2)
        .unwrap();
    sandbox
        .state_db
        .upsert_installed_file(&installed_rec3_collision)
        .unwrap();

    // Verify initial count of installed_files is 3
    let installed_before = sandbox.state_db.list_installed_files(None).unwrap();
    assert_eq!(installed_before.len(), 3);

    // 4. Run tidy with PurgeFromOs
    let engine = sandbox.sync_engine(&config, None);
    let report = engine
        .tidy(None, &lock, TidyOrphanPolicy::PurgeFromOs, false)
        .unwrap();

    assert_eq!(report.removed_os_orphans.len(), 1);
    assert_eq!(report.removed_os_orphans[0], orphan_path);
    assert!(!orphan_path.exists(), "Orphan file must be deleted from OS");

    // Synced file record must be removed
    let synced_after = sandbox.state_db.get_synced_file(&orphan_path_str).unwrap();
    assert!(
        synced_after.is_none(),
        "Orphan must be deleted from synced_files"
    );

    // CRITICAL ISOLATION ASSERTION: installed_files must be 100% untouched!
    let installed_after = sandbox.state_db.list_installed_files(None).unwrap();
    assert_eq!(
        installed_after.len(),
        3,
        "tidy must never delete or mutate installed_files table!"
    );
    let mut installed_paths: Vec<String> = installed_after
        .iter()
        .map(|r| r.target_path.clone())
        .collect();
    installed_paths.sort();
    let mut expected_paths = vec![
        installed_rec1.target_path.clone(),
        installed_rec2.target_path.clone(),
        installed_rec3_collision.target_path.clone(),
    ];
    expected_paths.sort();
    assert_eq!(installed_paths, expected_paths);
}

#[test]
fn test_tidy_installed_file_never_classified_as_synced_orphan() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml_str = r#"
[empty_group]
os-linux = "~"
files = "missing_file.txt"
"#;
    let config = RepoConfig::parse(toml_str).unwrap();

    // File exists on OS and is registered ONLY in installed_files (not in synced_files)
    let installed_target = sandbox.write_home_file("standalone.plugin", b"PLUGIN_BINARY_DATA");
    let target_str = installed_target.to_string_lossy().to_string();

    sandbox
        .state_db
        .upsert_installed_file(&InstalledFileRecord {
            target_path: target_str.clone(),
            repo_url: "https://github.com/org/plugin.git".into(),
            group_name: "plugin".into(),
            relative_path: "standalone.plugin".into(),
            backup_path: None,
            file_hash: blake3::hash(b"PLUGIN_BINARY_DATA").to_hex().to_string(),
            updated_at: 500,
        })
        .unwrap();

    let engine = sandbox.sync_engine(&config, None);
    let report = engine
        .tidy(None, &lock, TidyOrphanPolicy::PurgeFromOs, false)
        .unwrap();

    assert_eq!(
        report.removed_os_orphans.len(),
        0,
        "Installed file must not be recognized as a synced orphan"
    );
    assert!(
        installed_target.is_file(),
        "Installed file on OS must remain untouched"
    );

    let rec = sandbox
        .state_db
        .get_installed_file(&target_str)
        .unwrap()
        .expect("installed record exists");
    assert_eq!(rec.relative_path, "standalone.plugin");
}

// ---------------------------------------------------------------------------
// 6. Zero-Length Files & Dry-Run Immutability
// ---------------------------------------------------------------------------

#[test]
fn test_zero_length_file_sync_and_encryption_lifecycle() {
    let _keyring = TestKeyringGuard::new();
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();
    let (vault_cfg, vault_key) = sandbox.create_vault("strong-zero-len-pass");

    let toml_str = format!(
        r#"
[vault]
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[empty_group]
os-linux = "~"
files = """
empty_plain.txt
@empty_enc.sec
"""
"#,
        vault_cfg.vault_id, vault_cfg.password_slot, vault_cfg.recovery_slot
    );
    let config = RepoConfig::parse(&toml_str).unwrap();

    sandbox.write_home_file("empty_plain.txt", b"");
    sandbox.write_home_file("empty_enc.sec", b"");

    let engine = sandbox.sync_engine(&config, Some(&vault_key));

    // Import zero-length files
    let plans = engine.plan(None, &lock).unwrap();
    assert_eq!(plans.len(), 2);

    let import_report = engine.import_files(&plans, &lock, false).unwrap();
    assert_eq!(import_report.processed, 2);

    assert!(
        sandbox
            .repo_dir
            .join("empty_group/empty_plain.txt")
            .is_file()
    );
    assert!(
        sandbox
            .repo_dir
            .join("empty_group/empty_enc.sec.enc")
            .is_file()
    );

    // Second import: both must skip
    let plans2 = engine.plan(None, &lock).unwrap();
    let import_report2 = engine.import_files(&plans2, &lock, false).unwrap();
    assert_eq!(import_report2.skipped, 2);
    assert_eq!(import_report2.processed, 0);

    // Export: both must skip (idempotency)
    let export_report = engine.export_files(&plans2, &lock, false, false).unwrap();
    assert_eq!(export_report.skipped, 2);
    assert_eq!(export_report.processed, 0);
}

#[test]
fn test_dry_run_guarantees_zero_filesystem_and_database_mutations() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml_str = r#"
[group]
os-linux = "~"
files = "test.txt"
"#;
    let config = RepoConfig::parse(toml_str).unwrap();

    let target = sandbox.write_home_file("test.txt", b"HELLO_DRY_RUN");
    let engine = sandbox.sync_engine(&config, None);

    let plans = engine.plan(None, &lock).unwrap();
    assert_eq!(plans.len(), 1);

    // 1. Dry-run import
    let report_import = engine.import_files(&plans, &lock, true).unwrap();
    assert_eq!(report_import.processed, 1);

    // Repo file must NOT be written
    assert!(!sandbox.repo_dir.join("group/test.txt").exists());
    // DB must NOT have records
    let db_record = sandbox
        .state_db
        .get_synced_file(&target.to_string_lossy())
        .unwrap();
    assert!(db_record.is_none());

    // 2. Setup repo file, dry-run export to clean destination
    fs::remove_file(&target).unwrap();
    sandbox.write_repo_file("group/test.txt", b"REPO_VERSION");

    let plans_export = engine.plan(None, &lock).unwrap();
    let report_export = engine
        .export_files(&plans_export, &lock, false, true)
        .unwrap();
    assert_eq!(report_export.processed, 1);

    // OS target must NOT be written
    assert!(!target.exists());
    let db_record2 = sandbox
        .state_db
        .get_synced_file(&target.to_string_lossy())
        .unwrap();
    assert!(db_record2.is_none());
}

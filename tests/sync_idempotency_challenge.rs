mod common;

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

use common::{ChallengeSandbox, TestKeyringGuard};
use dotler::config::repo::RepoConfig;
use dotler::config::state::SyncedFileRecord;
use dotler::crypto::ExposeSecret;
use dotler::crypto::vault::EncryptedFile;
use dotler::engine::{EngineError, FileSyncStatus};

// ---------------------------------------------------------------------------
// 1. Hash-Match Idempotency & Repeated Export Verification
// ---------------------------------------------------------------------------

#[test]
fn test_export_idempotency_avoids_io_and_preserves_file_inode_and_mtime() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml_str = r#"
[shell]
os-nux = "~"
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
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[secrets]
os-nux = "~"
files = "credentials.env enc"
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
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[secrets]
os-nux = "~"
files = "token.txt enc"
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
os-nux = "~"
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
os-nux = "~"
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


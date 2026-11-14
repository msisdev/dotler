mod common;

use common::SyncTestSandbox;
use dotler::config::repo::RepoConfig;
use dotler::config::state::SyncedFileRecord;
use dotler::engine::EngineError;
use dotler::engine::sync::FileSyncStatus;

// ============================================================================
// Domain A: 3-Way Hash Reconciliation & Planning (`plan`)
// ============================================================================

#[test]
fn test_plan_all_synced_happy_path() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-nux = "~"
files = "test.sh"
"#;
    sandbox.write_dotler_toml(toml);
    let config = RepoConfig::parse(toml).unwrap();

    let content = b"echo hello\n";
    sandbox.write_home_file("test.sh", content);
    sandbox.write_repo_file("shell/test.sh", content);

    let hash = blake3::hash(content).to_hex().to_string();
    sandbox
        .state_db
        .upsert_synced_file(&SyncedFileRecord {
            target_path: sandbox
                .home_dir
                .join("test.sh")
                .to_string_lossy()
                .to_string(),
            repo_label: "default".to_string(),
            group_name: "shell".to_string(),
            relative_path: "test.sh".to_string(),
            file_hash: hash,
            updated_at: 1000,
        })
        .unwrap();

    let engine = sandbox.sync_engine(&config, None);
    let plans = engine.plan(None, &lock).unwrap();

    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].status, FileSyncStatus::Synced);
    assert_eq!(plans[0].relative_path, "test.sh");
}

#[test]
fn test_plan_detects_modified_locally() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-nux = "~"
files = "test.sh"
"#;
    sandbox.write_dotler_toml(toml);
    let config = RepoConfig::parse(toml).unwrap();

    let old_content = b"echo original\n";
    let new_local_content = b"echo local edit\n";
    sandbox.write_repo_file("shell/test.sh", old_content);
    sandbox.write_home_file("test.sh", new_local_content);

    let old_hash = blake3::hash(old_content).to_hex().to_string();
    sandbox
        .state_db
        .upsert_synced_file(&SyncedFileRecord {
            target_path: sandbox
                .home_dir
                .join("test.sh")
                .to_string_lossy()
                .to_string(),
            repo_label: "default".to_string(),
            group_name: "shell".to_string(),
            relative_path: "test.sh".to_string(),
            file_hash: old_hash,
            updated_at: 1000,
        })
        .unwrap();

    let engine = sandbox.sync_engine(&config, None);
    let plans = engine.plan(None, &lock).unwrap();

    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].status, FileSyncStatus::ModifiedLocally);
}

#[test]
fn test_plan_detects_modified_in_repo() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-nux = "~"
files = "test.sh"
"#;
    sandbox.write_dotler_toml(toml);
    let config = RepoConfig::parse(toml).unwrap();

    let old_content = b"echo original\n";
    let new_repo_content = b"echo repo update\n";
    sandbox.write_home_file("test.sh", old_content);
    sandbox.write_repo_file("shell/test.sh", new_repo_content);

    let old_hash = blake3::hash(old_content).to_hex().to_string();
    sandbox
        .state_db
        .upsert_synced_file(&SyncedFileRecord {
            target_path: sandbox
                .home_dir
                .join("test.sh")
                .to_string_lossy()
                .to_string(),
            repo_label: "default".to_string(),
            group_name: "shell".to_string(),
            relative_path: "test.sh".to_string(),
            file_hash: old_hash,
            updated_at: 1000,
        })
        .unwrap();

    let engine = sandbox.sync_engine(&config, None);
    let plans = engine.plan(None, &lock).unwrap();

    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].status, FileSyncStatus::ModifiedInRepo);
}

#[test]
fn test_plan_detects_missing_locally() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-nux = "~"
files = "test.sh"
"#;
    sandbox.write_dotler_toml(toml);
    let config = RepoConfig::parse(toml).unwrap();

    let content = b"echo hello\n";
    sandbox.write_repo_file("shell/test.sh", content);

    let hash = blake3::hash(content).to_hex().to_string();
    sandbox
        .state_db
        .upsert_synced_file(&SyncedFileRecord {
            target_path: sandbox
                .home_dir
                .join("test.sh")
                .to_string_lossy()
                .to_string(),
            repo_label: "default".to_string(),
            group_name: "shell".to_string(),
            relative_path: "test.sh".to_string(),
            file_hash: hash,
            updated_at: 1000,
        })
        .unwrap();

    let engine = sandbox.sync_engine(&config, None);
    let plans = engine.plan(None, &lock).unwrap();

    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].status, FileSyncStatus::MissingLocally);
}

#[test]
fn test_plan_detects_missing_in_repo() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-nux = "~"
files = "test.sh"
"#;
    sandbox.write_dotler_toml(toml);
    let config = RepoConfig::parse(toml).unwrap();

    let content = b"echo hello\n";
    sandbox.write_home_file("test.sh", content);

    let hash = blake3::hash(content).to_hex().to_string();
    sandbox
        .state_db
        .upsert_synced_file(&SyncedFileRecord {
            target_path: sandbox
                .home_dir
                .join("test.sh")
                .to_string_lossy()
                .to_string(),
            repo_label: "default".to_string(),
            group_name: "shell".to_string(),
            relative_path: "test.sh".to_string(),
            file_hash: hash,
            updated_at: 1000,
        })
        .unwrap();

    let engine = sandbox.sync_engine(&config, None);
    let plans = engine.plan(None, &lock).unwrap();

    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].status, FileSyncStatus::MissingInRepo);
}

#[test]
fn test_plan_detects_encryption_mismatch() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let (vault_cfg, vault_key) = sandbox.create_vault("correct-passphrase-1234");
    let toml = format!(
        r#"
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[secret]
os-nux = "~"
files = "secret.txt enc"
"#,
        vault_cfg.vault_id, vault_cfg.password_slot, vault_cfg.recovery_slot
    );
    sandbox.write_dotler_toml(&toml);
    let config = RepoConfig::parse(&toml).unwrap();

    // Plaintext in repo, but rule requests encrypted
    sandbox.write_repo_file("secret/secret.txt", b"my-plain-secret");
    sandbox.write_home_file("secret.txt", b"my-plain-secret");

    let engine = sandbox.sync_engine(&config, Some(&vault_key));
    let plans = engine.plan(None, &lock).unwrap();

    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].status, FileSyncStatus::EncryptionMismatch);
}

#[test]
fn test_plan_detects_orphaned_synced_files() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-nux = "~"
files = "new.sh"
"#;
    sandbox.write_dotler_toml(toml);
    let config = RepoConfig::parse(toml).unwrap();

    // DB has old.sh which is not in files rule
    sandbox
        .state_db
        .upsert_synced_file(&SyncedFileRecord {
            target_path: sandbox
                .home_dir
                .join("old.sh")
                .to_string_lossy()
                .to_string(),
            repo_label: "default".to_string(),
            group_name: "shell".to_string(),
            relative_path: "old.sh".to_string(),
            file_hash: "abcd".to_string(),
            updated_at: 1000,
        })
        .unwrap();

    let engine = sandbox.sync_engine(&config, None);
    let plans = engine.plan(None, &lock).unwrap();

    let orphan = plans.iter().find(|p| p.relative_path == "old.sh");
    assert!(orphan.is_some());
    assert_eq!(orphan.unwrap().status, FileSyncStatus::Orphaned);
}

// ============================================================================
// Domain B: Deterministic Export & Idempotency (`export_files`)
// ============================================================================

#[test]
fn test_export_fresh_deployment_atomic_staging() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-nux = "~"
files = "app.conf"
"#;
    sandbox.write_dotler_toml(toml);
    let config = RepoConfig::parse(toml).unwrap();

    let content = b"port = 8080\n";
    sandbox.write_repo_file("shell/app.conf", content);

    let engine = sandbox.sync_engine(&config, None);
    let plans = engine.plan(None, &lock).unwrap();
    assert_eq!(plans[0].status, FileSyncStatus::ModifiedInRepo);

    let report = engine.export_files(&plans, &lock, false, false).unwrap();
    assert_eq!(report.processed, 1);
    assert_eq!(report.skipped, 0);

    let deployed = sandbox.read_home_file("app.conf").unwrap();
    assert_eq!(deployed, content);

    let record = sandbox
        .state_db
        .get_synced_file(&sandbox.home_dir.join("app.conf").to_string_lossy())
        .unwrap()
        .unwrap();
    assert_eq!(record.file_hash, blake3::hash(content).to_hex().to_string());
}

#[test]
fn test_export_hash_match_idempotency_skip() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-nux = "~"
files = "app.conf"
"#;
    sandbox.write_dotler_toml(toml);
    let config = RepoConfig::parse(toml).unwrap();

    let content = b"port = 8080\n";
    sandbox.write_repo_file("shell/app.conf", content);
    sandbox.write_home_file("app.conf", content);

    let engine = sandbox.sync_engine(&config, None);
    let plans = engine.plan(None, &lock).unwrap();

    let report = engine.export_files(&plans, &lock, false, false).unwrap();
    assert_eq!(report.processed, 0);
    assert_eq!(report.skipped, 1);

    // State DB should be committed as Synced
    let record = sandbox
        .state_db
        .get_synced_file(&sandbox.home_dir.join("app.conf").to_string_lossy())
        .unwrap();
    assert!(record.is_some());
}

#[test]
fn test_export_local_conflict_blocks_write_without_force() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-nux = "~"
files = "app.conf"
"#;
    sandbox.write_dotler_toml(toml);
    let config = RepoConfig::parse(toml).unwrap();

    let repo_content = b"port = 8080\n";
    let local_content = b"port = 9090\n";
    sandbox.write_repo_file("shell/app.conf", repo_content);
    sandbox.write_home_file("app.conf", local_content);

    // Record previous sync matching repo
    let old_hash = blake3::hash(repo_content).to_hex().to_string();
    sandbox
        .state_db
        .upsert_synced_file(&SyncedFileRecord {
            target_path: sandbox
                .home_dir
                .join("app.conf")
                .to_string_lossy()
                .to_string(),
            repo_label: "default".to_string(),
            group_name: "shell".to_string(),
            relative_path: "app.conf".to_string(),
            file_hash: old_hash,
            updated_at: 1000,
        })
        .unwrap();

    let engine = sandbox.sync_engine(&config, None);
    let plans = engine.plan(None, &lock).unwrap();

    let err = engine
        .export_files(&plans, &lock, false, false)
        .unwrap_err();
    match err {
        EngineError::SyncConflict { .. } => {}
        _ => panic!("Expected SyncConflict, got: {:?}", err),
    }

    // Local file was not modified
    assert_eq!(sandbox.read_home_file("app.conf").unwrap(), local_content);
}

#[test]
fn test_export_force_overwrites_conflict() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-nux = "~"
files = "app.conf"
"#;
    sandbox.write_dotler_toml(toml);
    let config = RepoConfig::parse(toml).unwrap();

    let repo_content = b"port = 8080\n";
    let local_content = b"port = 9090\n";
    sandbox.write_repo_file("shell/app.conf", repo_content);
    sandbox.write_home_file("app.conf", local_content);

    let old_hash = blake3::hash(repo_content).to_hex().to_string();
    sandbox
        .state_db
        .upsert_synced_file(&SyncedFileRecord {
            target_path: sandbox
                .home_dir
                .join("app.conf")
                .to_string_lossy()
                .to_string(),
            repo_label: "default".to_string(),
            group_name: "shell".to_string(),
            relative_path: "app.conf".to_string(),
            file_hash: old_hash,
            updated_at: 1000,
        })
        .unwrap();

    let engine = sandbox.sync_engine(&config, None);
    let plans = engine.plan(None, &lock).unwrap();

    let report = engine.export_files(&plans, &lock, true, false).unwrap();
    assert_eq!(report.processed, 1);

    // Local file was overwritten with repo content
    assert_eq!(sandbox.read_home_file("app.conf").unwrap(), repo_content);
}

#[test]
fn test_export_decrypts_encrypted_file_to_os() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let (vault_cfg, vault_key) = sandbox.create_vault("passphrase-for-export");
    let toml = format!(
        r#"
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[secret]
os-nux = "~"
files = "secret.txt enc"
"#,
        vault_cfg.vault_id, vault_cfg.password_slot, vault_cfg.recovery_slot
    );
    sandbox.write_dotler_toml(&toml);
    let config = RepoConfig::parse(&toml).unwrap();

    let plaintext = b"export-me-safely-123\n";
    let enc = vault_key.encrypt_file(plaintext).unwrap();
    sandbox.write_repo_file("secret/secret.txt.enc", &enc.to_bytes());

    let engine = sandbox.sync_engine(&config, Some(&vault_key));
    let plans = engine.plan(None, &lock).unwrap();

    let report = engine.export_files(&plans, &lock, false, false).unwrap();
    assert_eq!(report.processed, 1);

    let exported = sandbox.read_home_file("secret.txt").unwrap();
    assert_eq!(exported, plaintext);
}

#[test]
fn test_export_dry_run_leaves_filesystem_and_db_untouched() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-nux = "~"
files = "dry.conf"
"#;
    sandbox.write_dotler_toml(toml);
    let config = RepoConfig::parse(toml).unwrap();

    sandbox.write_repo_file("shell/dry.conf", b"dry-run-data\n");

    let engine = sandbox.sync_engine(&config, None);
    let plans = engine.plan(None, &lock).unwrap();

    let report = engine.export_files(&plans, &lock, false, true).unwrap();
    assert_eq!(report.processed, 1);

    assert!(sandbox.read_home_file("dry.conf").is_none());
    let record = sandbox
        .state_db
        .get_synced_file(&sandbox.home_dir.join("dry.conf").to_string_lossy())
        .unwrap();
    assert!(record.is_none());
}


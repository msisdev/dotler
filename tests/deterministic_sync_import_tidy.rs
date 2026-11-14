mod common;

use std::fs;

use common::SyncTestSandbox;
use dotler::config::repo::{OsInfo, RepoConfig};
use dotler::config::state::{InstalledFileRecord, SyncedFileRecord};
use dotler::crypto::ExposeSecret;
use dotler::crypto::vault::EncryptedFile;
use dotler::engine::sync::{SyncEngine, TidyOrphanPolicy};

// ============================================================================
// Domain C: Deterministic Import & Hash Skipping (`import_files`)
// ============================================================================

#[test]
fn test_import_fresh_files_to_repo_atomic_staging() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-nux = "~"
files = "script.sh"
"#;
    sandbox.write_dotler_toml(toml);
    let config = RepoConfig::parse(toml).unwrap();

    let content = b"#!/bin/sh\necho test\n";
    sandbox.write_home_file("script.sh", content);

    let engine = sandbox.sync_engine(&config, None);
    let plans = engine.plan(None, &lock).unwrap();

    let report = engine.import_files(&plans, &lock, false).unwrap();
    assert_eq!(report.processed, 1);

    let repo_file = sandbox.read_repo_file("shell/script.sh").unwrap();
    assert_eq!(repo_file, content);

    let record = sandbox
        .state_db
        .get_synced_file(&sandbox.home_dir.join("script.sh").to_string_lossy())
        .unwrap()
        .unwrap();
    assert_eq!(record.file_hash, blake3::hash(content).to_hex().to_string());
}

#[test]
fn test_import_plaintext_hash_match_skips_reencryption() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let (vault_cfg, vault_key) = sandbox.create_vault("passphrase-import-skip");
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

    let content = b"secret-token-abcdef\n";
    sandbox.write_home_file("secret.txt", content);

    let engine = sandbox.sync_engine(&config, Some(&vault_key));
    let plans = engine.plan(None, &lock).unwrap();

    let report1 = engine.import_files(&plans, &lock, false).unwrap();
    assert_eq!(report1.processed, 1);

    let enc_bytes_1 = sandbox.read_repo_file("secret/secret.txt.enc").unwrap();

    // Re-plan and re-import identical content
    let plans2 = engine.plan(None, &lock).unwrap();
    let report2 = engine.import_files(&plans2, &lock, false).unwrap();
    assert_eq!(report2.skipped, 1);
    assert_eq!(report2.processed, 0);

    let enc_bytes_2 = sandbox.read_repo_file("secret/secret.txt.enc").unwrap();
    assert_eq!(enc_bytes_1, enc_bytes_2);
}

#[test]
fn test_import_reencrypts_when_plaintext_modified() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let (vault_cfg, vault_key) = sandbox.create_vault("passphrase-reencrypt");
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

    sandbox.write_home_file("secret.txt", b"v1\n");
    let engine = sandbox.sync_engine(&config, Some(&vault_key));
    let plans1 = engine.plan(None, &lock).unwrap();
    engine.import_files(&plans1, &lock, false).unwrap();

    // Modify plaintext
    sandbox.write_home_file("secret.txt", b"v2\n");
    let plans2 = engine.plan(None, &lock).unwrap();
    let report2 = engine.import_files(&plans2, &lock, false).unwrap();
    assert_eq!(report2.processed, 1);

    let enc_bytes = sandbox.read_repo_file("secret/secret.txt.enc").unwrap();
    let enc_file = EncryptedFile::from_bytes(&enc_bytes).unwrap();
    let decrypted = vault_key.decrypt_file(&enc_file).unwrap();
    assert_eq!(decrypted.expose_secret(), b"v2\n");
}

#[test]
fn test_import_per_file_wal_db_commit() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[batch]
os-nux = "~"
files = """
file1.txt
file2.txt
"""
"#;
    sandbox.write_dotler_toml(toml);
    let config = RepoConfig::parse(toml).unwrap();

    sandbox.write_home_file("file1.txt", b"content1\n");
    sandbox.write_home_file("file2.txt", b"content2\n");

    let engine = sandbox.sync_engine(&config, None);
    let plans = engine.plan(None, &lock).unwrap();

    let report = engine.import_files(&plans, &lock, false).unwrap();
    assert_eq!(report.processed, 2);

    let rec1 = sandbox
        .state_db
        .get_synced_file(&sandbox.home_dir.join("file1.txt").to_string_lossy())
        .unwrap();
    let rec2 = sandbox
        .state_db
        .get_synced_file(&sandbox.home_dir.join("file2.txt").to_string_lossy())
        .unwrap();
    assert!(rec1.is_some());
    assert!(rec2.is_some());
}

// ============================================================================
// Domain D: Deterministic Tidy & Table Isolation (`tidy`)
// ============================================================================

#[test]
fn test_tidy_converts_plaintext_to_encrypted_in_place() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let (vault_cfg, vault_key) = sandbox.create_vault("tidy-key");
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

    sandbox.write_repo_file("secret/secret.txt", b"secret-plain\n");

    let engine = sandbox.sync_engine(&config, Some(&vault_key));
    let report = engine
        .tidy(None, &lock, TidyOrphanPolicy::KeepOnOs, false)
        .unwrap();
    assert_eq!(report.encrypted_in_repo, 1);

    assert!(sandbox.read_repo_file("secret/secret.txt").is_none());
    let enc_bytes = sandbox.read_repo_file("secret/secret.txt.enc").unwrap();
    let enc_file = EncryptedFile::from_bytes(&enc_bytes).unwrap();
    let dec = vault_key.decrypt_file(&enc_file).unwrap();
    assert_eq!(dec.expose_secret(), b"secret-plain\n");
}

#[test]
fn test_tidy_converts_encrypted_to_plaintext_in_place() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let (vault_cfg, vault_key) = sandbox.create_vault("tidy-decrypt");
    let toml = format!(
        r#"
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[secret]
os-nux = "~"
files = "secret.txt"
"#,
        vault_cfg.vault_id, vault_cfg.password_slot, vault_cfg.recovery_slot
    );
    sandbox.write_dotler_toml(&toml);
    let config = RepoConfig::parse(&toml).unwrap();

    let enc = vault_key.encrypt_file(b"secret-plain\n").unwrap();
    sandbox.write_repo_file("secret/secret.txt.enc", &enc.to_bytes());

    let engine = sandbox.sync_engine(&config, Some(&vault_key));
    let report = engine
        .tidy(None, &lock, TidyOrphanPolicy::KeepOnOs, false)
        .unwrap();
    assert_eq!(report.decrypted_in_repo, 1);

    assert!(sandbox.read_repo_file("secret/secret.txt.enc").is_none());
    let plain = sandbox.read_repo_file("secret/secret.txt").unwrap();
    assert_eq!(plain, b"secret-plain\n");
}

#[test]
fn test_tidy_orphan_keep_policy_preserves_os_file() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-nux = "~"
files = "active.sh"
"#;
    sandbox.write_dotler_toml(toml);
    let config = RepoConfig::parse(toml).unwrap();

    let orphan_os_path = sandbox.write_home_file("orphan.sh", b"leave-me\n");
    sandbox
        .state_db
        .upsert_synced_file(&SyncedFileRecord {
            target_path: orphan_os_path.to_string_lossy().to_string(),
            repo_label: "default".to_string(),
            group_name: "shell".to_string(),
            relative_path: "orphan.sh".to_string(),
            file_hash: "1234".to_string(),
            updated_at: 1000,
        })
        .unwrap();

    let engine = sandbox.sync_engine(&config, None);
    let report = engine
        .tidy(None, &lock, TidyOrphanPolicy::KeepOnOs, false)
        .unwrap();

    assert_eq!(report.untracked_kept_orphans.len(), 1);
    assert_eq!(report.removed_os_orphans.len(), 0);
    assert!(orphan_os_path.is_file());

    let record = sandbox
        .state_db
        .get_synced_file(&orphan_os_path.to_string_lossy())
        .unwrap();
    assert!(record.is_none());
}

#[test]
fn test_tidy_orphan_purge_policy_deletes_os_file() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-nux = "~"
files = "active.sh"
"#;
    sandbox.write_dotler_toml(toml);
    let config = RepoConfig::parse(toml).unwrap();

    let orphan_os_path = sandbox.write_home_file("orphan.sh", b"delete-me\n");
    sandbox
        .state_db
        .upsert_synced_file(&SyncedFileRecord {
            target_path: orphan_os_path.to_string_lossy().to_string(),
            repo_label: "default".to_string(),
            group_name: "shell".to_string(),
            relative_path: "orphan.sh".to_string(),
            file_hash: "1234".to_string(),
            updated_at: 1000,
        })
        .unwrap();

    let engine = sandbox.sync_engine(&config, None);
    let report = engine
        .tidy(None, &lock, TidyOrphanPolicy::PurgeFromOs, false)
        .unwrap();

    assert_eq!(report.removed_os_orphans.len(), 1);
    assert!(!orphan_os_path.exists());

    let record = sandbox
        .state_db
        .get_synced_file(&orphan_os_path.to_string_lossy())
        .unwrap();
    assert!(record.is_none());
}

#[test]
fn test_tidy_strict_physical_isolation_from_installed_files() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-nux = "~"
files = "active.sh"
"#;
    sandbox.write_dotler_toml(toml);
    let config = RepoConfig::parse(toml).unwrap();

    sandbox
        .state_db
        .upsert_installed_file(&InstalledFileRecord {
            target_path: "/dummy/target".to_string(),
            repo_url: "https://example.com/repo.git".to_string(),
            group_name: "installed_group".to_string(),
            relative_path: "file.txt".to_string(),
            file_hash: "hash".to_string(),
            updated_at: 1000,
            backup_path: Some("/dummy/backup".to_string()),
        })
        .unwrap();

    let engine = sandbox.sync_engine(&config, None);
    engine
        .tidy(None, &lock, TidyOrphanPolicy::PurgeFromOs, false)
        .unwrap();

    let installed = sandbox
        .state_db
        .get_installed_file("/dummy/target")
        .unwrap();
    assert!(installed.is_some());
}

#[test]
fn test_import_files_upserts_synced_files_on_hash_match() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    // Write file in OS
    sandbox.write_home_file(".bashrc", b"export FOO=1\n");
    // Write matching file in repo
    sandbox.write_repo_file("shell/.bashrc", b"export FOO=1\n");

    let toml = r#"
[shell]
os-nux = "~"
files = ".bashrc"
"#;
    let repo_config = RepoConfig::parse(toml).unwrap();
    let engine = sandbox.sync_engine(&repo_config, None);

    let plans = engine.plan(None, &lock).unwrap();
    assert_eq!(plans.len(), 1);

    // Initial DB should have 0 synced files
    assert!(sandbox.state_db.list_synced_files(None).unwrap().is_empty());

    // Import files should skip writing to disk because hash matches,
    // but MUST commit the record to state.db
    let report = engine.import_files(&plans, &lock, false).unwrap();
    assert_eq!(report.skipped, 1);
    assert_eq!(report.processed, 0);

    // Verify DB ledger now has the synced file
    let records = sandbox.state_db.list_synced_files(None).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].relative_path, ".bashrc");
    assert_eq!(
        records[0].file_hash,
        blake3::hash(b"export FOO=1\n").to_hex().to_string()
    );
}

#[test]
fn test_sync_wildcard_home_filters_internal_state_and_git() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    // 1. Populate home directory with internal dotler state, repo, git, and dotfiles
    sandbox.write_home_file(".bashrc", b"export PATH=/bin\n");
    sandbox.write_home_file(".zshrc", b"export ZSH=1\n");
    sandbox.write_home_file(".git/config", b"[core]\nrepositoryformatversion = 0\n");
    sandbox.write_home_file(".git/HEAD", b"ref: refs/heads/main\n");
    sandbox.write_home_file(".config/dotler/config.toml", b"default_repo = 'default'\n");

    // Also repo itself inside home
    let internal_repo = sandbox.home_dir.join("dotfiles");
    fs::create_dir_all(&internal_repo).unwrap();
    fs::write(
        internal_repo.join("dotler.toml"),
        "[shell]\nos-nux = \"~\"\nfiles = \"*\"\n",
    )
    .unwrap();

    let toml = r#"
[shell]
os-nux = "~"
os-mac = "~"
files = "*"
"#;
    let repo_config = RepoConfig::parse(toml).unwrap();
    let engine = SyncEngine::new(
        "default",
        &internal_repo,
        &repo_config,
        &sandbox.state_db,
        vec![],
        OsInfo::detect(),
        None,
    )
    .with_home_dir(&sandbox.home_dir);

    // 2. Plan synchronization
    let plans = engine.plan(None, &lock).unwrap();

    // Verify plans only contain .bashrc and .zshrc
    let candidate_paths: Vec<String> = plans.iter().map(|p| p.relative_path.clone()).collect();
    assert!(
        candidate_paths.contains(&".bashrc".to_string()),
        "Must contain .bashrc: {:?}",
        candidate_paths
    );
    assert!(
        candidate_paths.contains(&".zshrc".to_string()),
        "Must contain .zshrc: {:?}",
        candidate_paths
    );

    // Verify internal state, git, and repo files are completely excluded
    for p in &candidate_paths {
        assert!(
            !p.starts_with(".config/dotler"),
            "Internal .config/dotler leaked into candidates: {}",
            p
        );
        assert!(
            !p.split('/').any(|s| s == ".git"),
            ".git directory leaked into candidates: {}",
            p
        );
        assert!(
            !p.starts_with("dotfiles"),
            "Repository directory leaked into candidates: {}",
            p
        );
    }

    // 3. Execute import and assert no internal files are placed into repo
    let report = engine.import_files(&plans, &lock, false).unwrap();
    assert_eq!(report.processed, 2);

    assert!(internal_repo.join("shell").join(".bashrc").is_file());
    assert!(internal_repo.join("shell").join(".zshrc").is_file());
    assert!(
        !internal_repo
            .join("shell")
            .join(".config")
            .join("dotler")
            .exists()
    );
    assert!(!internal_repo.join("shell").join(".git").exists());
    assert!(!internal_repo.join("shell").join("dotfiles").exists());
}

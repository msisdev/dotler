mod common;

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use common::{ChallengeSandbox, TestKeyringGuard};
use dotler::config::repo::RepoConfig;
use dotler::config::state::{InstalledFileRecord, SyncedFileRecord, TMP_FILE_PREFIX};
use dotler::engine::{TidyOrphanPolicy, write_file_safe};

// ---------------------------------------------------------------------------
// 4. Interruption Safety, Staging Isolation, & Unix Permissions
// ---------------------------------------------------------------------------

#[test]
fn test_write_file_safe_same_directory_staging_and_clean_replacement() {
    let sandbox = ChallengeSandbox::new();
    let dest_file = sandbox.home_dir.join("subdir/nested/dest.txt");

    let initial = b"INITIAL_DATA";
    write_file_safe(&dest_file, initial).expect("initial atomic write");
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
    write_file_safe(&dest_file, updated).expect("update atomic write");
    assert_eq!(fs::read(&dest_file).unwrap(), updated);
}

#[test]
#[cfg(unix)]
fn test_write_file_safe_preserves_unix_permissions() {
    let sandbox = ChallengeSandbox::new();
    let exec_file = sandbox.home_dir.join("bin/script.sh");

    // Create target with executable permissions 0o755
    fs::create_dir_all(exec_file.parent().unwrap()).unwrap();
    fs::write(&exec_file, b"#!/bin/sh\necho 1\n").unwrap();
    fs::set_permissions(&exec_file, fs::Permissions::from_mode(0o755)).unwrap();

    let meta1 = fs::metadata(&exec_file).unwrap();
    assert_eq!(meta1.permissions().mode() & 0o777, 0o755);

    // Atomic replace
    write_file_safe(&exec_file, b"#!/bin/sh\necho 2\n").unwrap();
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

    write_file_safe(&secret_file, b"NEW_KEY_DATA").unwrap();
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
os-nux = "~"
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
os-nux = "~"
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
os-nux = "~"
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
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[empty_group]
os-nux = "~"
files = """
empty_plain.txt
empty_enc.sec enc
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
os-nux = "~"
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

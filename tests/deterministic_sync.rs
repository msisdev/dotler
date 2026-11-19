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
    sandbox.write_repo_file("secret/secret.txt.dotler.enc", &enc.to_bytes());

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

#[test]
fn test_e2e_cli_in_project_cwd_encrypted_sync_and_storage_overlap_guard() {
    let tmp = tempfile::tempdir().unwrap();
    let home_dir = tmp.path().join("home");
    let project_dir = tmp.path().join("project");
    std::fs::create_dir_all(home_dir.join(".ssh")).unwrap();
    std::fs::create_dir_all(project_dir.join("private")).unwrap();
    std::fs::write(home_dir.join(".ssh/id_rsa"), b"HOME_KEY\n").unwrap();

    let (vcfg, vkey) = SyncTestSandbox::new().create_vault("cli-cwd-pass-123");
    let toml = format!(
        "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n\n[secrets]\nos-nux = \".\"\nos-mac = \".\"\nos-win = \".\"\nos-bsd = \".\"\nfiles = \"\"\"\n.env enc\nprivate/* enc=full\n\"\"\"\n",
        vcfg.vault_id, vcfg.password_slot, vcfg.recovery_slot
    );
    std::fs::write(project_dir.join("dotler.toml"), &toml).unwrap();
    std::fs::write(project_dir.join(".env"), b"API_SECRET=hello\n").unwrap();
    std::fs::write(project_dir.join("private/token.txt"), b"TOKEN_ABC\n").unwrap();

    let run_cli = |dir: &std::path::Path, args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_dotler"))
            .env("HOME", &home_dir)
            .env("DOTLER_MOCK_KEYRING", "1")
            .env("DOTLER_PASSPHRASE", "cli-cwd-pass-123")
            .current_dir(dir)
            .stdin(std::process::Stdio::null())
            .args(args)
            .output()
            .unwrap()
    };

    // 1. `dotler check` succeeds on in-project `.` group.
    let check_out = run_cli(&project_dir, &["check", "--json"]);
    assert_eq!(
        check_out.status.code(),
        Some(0),
        "stdout: {} stderr: {}",
        String::from_utf8_lossy(&check_out.stdout),
        String::from_utf8_lossy(&check_out.stderr)
    );

    // 2. `dotler import -y` encrypts `.env` and `private/token.txt` into `secrets/`.
    let imp_out = run_cli(&project_dir, &["import", "-y", "--json"]);
    assert_eq!(
        imp_out.status.code(),
        Some(0),
        "stdout: {} stderr: {}",
        String::from_utf8_lossy(&imp_out.stdout),
        String::from_utf8_lossy(&imp_out.stderr)
    );
    assert!(project_dir.join("secrets/.env.dotler.enc").is_file());
    let expected_fenc = project_dir
        .join("secrets")
        .join(vkey.derive_full_enc_filename("private/token.txt"));
    assert!(expected_fenc.is_file());

    // 3. Delete plaintext OS files and restore via `dotler export -y`.
    std::fs::remove_file(project_dir.join(".env")).unwrap();
    std::fs::remove_file(project_dir.join("private/token.txt")).unwrap();
    std::fs::remove_dir(project_dir.join("private")).unwrap();

    let exp_out = run_cli(&project_dir, &["export", "-y", "--json"]);
    assert_eq!(
        exp_out.status.code(),
        Some(0),
        "stdout: {} stderr: {}",
        String::from_utf8_lossy(&exp_out.stdout),
        String::from_utf8_lossy(&exp_out.stderr)
    );
    assert_eq!(
        std::fs::read(project_dir.join(".env")).unwrap(),
        b"API_SECRET=hello\n"
    );
    assert_eq!(
        std::fs::read(project_dir.join("private/token.txt")).unwrap(),
        b"TOKEN_ABC\n"
    );
    assert_eq!(
        std::fs::read_to_string(project_dir.join("dotler.toml")).unwrap(),
        toml
    );

    // 4. Symlink inside project pointing outside `cwd` (even into `home_dir`) must exit 3.
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            home_dir.join(".ssh/id_rsa"),
            project_dir.join("private/escape.key"),
        )
        .unwrap();
        let esc_out = run_cli(&project_dir, &["status", "--json"]);
        assert_eq!(esc_out.status.code(), Some(3));
        std::fs::remove_file(project_dir.join("private/escape.key")).unwrap();
    }

    // 5. Overlapping group storage `[config]` (`os-nux = "./config"` or `files = "config/x"`) must exit 3.
    std::fs::write(
        project_dir.join("dotler.toml"),
        "[config]\nos-nux = \"./config\"\nos-mac = \"./config\"\nos-win = \"./config\"\nos-bsd = \"./config\"\nfiles = \"app.env\"\n",
    )
    .unwrap();
    let overlap_out = run_cli(&project_dir, &["check", "--json"]);
    assert_eq!(overlap_out.status.code(), Some(3));
}

#[test]
fn test_e2e_cli_cwd_multi_project_tidy_purge_isolation() {
    let tmp = tempfile::tempdir().unwrap();
    let home_dir = tmp.path().join("home");
    let repo_dir = home_dir.join("shared-proj-repo");
    let project_a = tmp.path().join("project_a");
    let project_b = tmp.path().join("project_b");
    std::fs::create_dir_all(home_dir.join(".config/dotler")).unwrap();
    std::fs::create_dir_all(repo_dir.join("proj/keep")).unwrap();
    std::fs::create_dir_all(repo_dir.join("proj/drop")).unwrap();
    std::fs::create_dir_all(&project_a).unwrap();
    std::fs::create_dir_all(&project_b).unwrap();

    std::fs::write(
        home_dir.join(".config/dotler/config.toml"),
        "default_devices = []\ndefault_repo = \"shared\"\nuse_keyring = true\n\n[repos]\nshared = \"~/shared-proj-repo\"\n",
    )
    .unwrap();
    std::fs::write(
        repo_dir.join("dotler.toml"),
        "[proj]\nos-nux = \".\"\nos-mac = \".\"\nos-win = \".\"\nos-bsd = \".\"\nfiles = \"\"\"\nkeep/a.env\ndrop/old.env\n\"\"\"\n",
    )
    .unwrap();
    std::fs::write(repo_dir.join("proj/keep/a.env"), b"KEEP=1\n").unwrap();
    std::fs::write(repo_dir.join("proj/drop/old.env"), b"OLD=1\n").unwrap();

    let run_cli = |dir: &std::path::Path, args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_dotler"))
            .env("HOME", &home_dir)
            .env("DOTLER_MOCK_KEYRING", "1")
            .current_dir(dir)
            .stdin(std::process::Stdio::null())
            .args(args)
            .output()
            .unwrap()
    };

    assert_eq!(
        run_cli(&project_a, &["export", "-y"]).status.code(),
        Some(0)
    );
    assert_eq!(
        run_cli(&project_b, &["export", "-y"]).status.code(),
        Some(0)
    );
    assert!(project_a.join("drop/old.env").is_file());
    assert!(project_b.join("drop/old.env").is_file());

    // Remove `drop/old.env` from manifest and run `tidy --purge -y` inside `project_b`.
    std::fs::write(
        repo_dir.join("dotler.toml"),
        "[proj]\nos-nux = \".\"\nos-mac = \".\"\nos-win = \".\"\nos-bsd = \".\"\nfiles = \"keep/a.env\"\n",
    )
    .unwrap();
    let tidy_out = run_cli(&project_b, &["tidy", "--purge", "-y", "--json"]);
    assert_eq!(
        tidy_out.status.code(),
        Some(0),
        "stdout: {} stderr: {}",
        String::from_utf8_lossy(&tidy_out.stdout),
        String::from_utf8_lossy(&tidy_out.stderr)
    );

    assert!(!project_b.join("drop").exists());
    assert!(project_b.join("keep/a.env").is_file());
    assert!(project_a.join("drop/old.env").is_file());
    assert!(project_a.join("keep/a.env").is_file());
}

//! Adversarial stress test suite for Phase 3 Engine remediation.
//!
//! Validates:
//! 1. Empty shorthand slugs in `parse_url` (gh:, gl:, cb:, srht:, bb:)
//! 2. Path security on `path_override` in `install_remote` (path traversal, absolute paths outside home, .git, config)
//! 3. Repeated install and uninstall stress on fresh files and pre-existing files
//! 4. Database synchronization in `import_files` when skipping on hash match

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;

use dotler::config::ConfigError;
use dotler::config::repo::{OsInfo, RepoConfig};
use dotler::config::state::{DotlerLock, DotlerLockGuard, StateDb};
use dotler::crypto::SecretString;
use dotler::crypto::vault::init_vault;
use dotler::engine::EngineError;
use dotler::engine::remote::{install_remote, parse_url, uninstall_remote};
use dotler::engine::sync::{FileSyncStatus, SyncEngine};

struct TestSandbox {
    _root: TempDir,
    home_dir: PathBuf,
    _config_dir: PathBuf,
    state_db: StateDb,
    lock_path: PathBuf,
}

impl TestSandbox {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("create temp sandbox root");
        let home_dir = root.path().join("home");
        let config_dir = home_dir.join(".config").join("dotler");
        fs::create_dir_all(&config_dir).expect("create config dir");

        let db_path = config_dir.join("state.db");
        let state_db = StateDb::open(&db_path).expect("open state db");
        let lock_path = config_dir.join("dotler.lock");

        Self {
            _root: root,
            home_dir,
            _config_dir: config_dir,
            state_db,
            lock_path,
        }
    }

    fn acquire_lock(&self) -> DotlerLockGuard {
        let lock = DotlerLock::new(self.lock_path.clone());
        lock.acquire(Duration::from_millis(5000), Duration::from_millis(50))
            .expect("acquire lock")
    }

    fn write_home_file(&self, rel: &str, content: &[u8]) -> PathBuf {
        let path = self.home_dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, content).unwrap();
        path
    }
}

struct TestGitRepo {
    _temp: TempDir,
    clone_url: String,
}

impl TestGitRepo {
    fn new(dotler_toml: &str, files: &[(&str, &[u8])]) -> Self {
        let temp = tempfile::tempdir().expect("create mock git tempdir");
        let worktree = temp.path().join("worktree");
        let bare = temp.path().join("repo.git");
        fs::create_dir_all(&worktree).unwrap();

        let run = |args: &[&str], dir: &Path| {
            let status = Command::new("git")
                .args(args)
                .current_dir(dir)
                .status()
                .expect("git exec");
            assert!(status.success(), "git command failed: {:?}", args);
        };

        run(&["init", "-b", "main"], &worktree);
        run(
            &["config", "user.email", "challenger@test.local"],
            &worktree,
        );
        run(&["config", "user.name", "Challenger"], &worktree);

        fs::write(worktree.join("dotler.toml"), dotler_toml).unwrap();
        for (rel, data) in files {
            let p = worktree.join(rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(p, data).unwrap();
        }

        run(&["add", "."], &worktree);
        run(&["commit", "-m", "Initial commit"], &worktree);
        run(
            &[
                "clone",
                "--bare",
                worktree.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            temp.path(),
        );

        Self {
            _temp: temp,
            clone_url: format!("file://{}", bare.display()),
        }
    }
}

#[test]
fn test_adversarial_parse_url_empty_slugs_and_malformed() {
    let empty_slug_cases = [
        "gh:", "gh:/", "gh://", "gh:///", "gl:", "gl:/", "gl://", "cb:", "cb:/", "cb://", "srht:",
        "srht:/", "srht://", "bb:", "bb:/", "bb://",
    ];

    for case in empty_slug_cases {
        let res = parse_url(case);
        assert!(
            res.is_err(),
            "Expected parse_url to reject empty slug '{case}', but got: {:?}",
            res
        );
        match res.unwrap_err() {
            EngineError::InvalidUrlFormat { reason, .. } => {
                assert_eq!(
                    reason, "Repository slug cannot be empty",
                    "Mismatch for case '{case}'"
                );
            }
            other => panic!("Expected InvalidUrlFormat for '{case}', got: {:?}", other),
        }
    }

    let empty_url_cases = ["", "   ", "\t\n"];
    for case in empty_url_cases {
        let res = parse_url(case);
        assert!(res.is_err(), "Expected parse_url to reject '{case}'");
        match res.unwrap_err() {
            EngineError::InvalidUrlFormat { reason, .. } => {
                assert_eq!(reason, "URL cannot be empty");
            }
            other => panic!("Expected InvalidUrlFormat for '{case}', got: {:?}", other),
        }
    }

    // Verify valid shorthands parse as expected
    assert_eq!(
        parse_url("gh:user/repo").unwrap().clone_url,
        "https://github.com/user/repo.git"
    );
    assert_eq!(
        parse_url("gl:user/repo").unwrap().clone_url,
        "https://gitlab.com/user/repo.git"
    );
    assert_eq!(
        parse_url("cb:user/repo").unwrap().clone_url,
        "https://codeberg.org/user/repo.git"
    );
    assert_eq!(
        parse_url("srht:~user/repo").unwrap().clone_url,
        "https://git.sr.ht/~user/repo"
    );
    assert_eq!(
        parse_url("bb:user/repo").unwrap().clone_url,
        "https://bitbucket.org/user/repo.git"
    );
}

#[test]
fn test_adversarial_path_override_security_checks() {
    let sandbox = TestSandbox::new();
    let lock = sandbox.acquire_lock();

    let remote_toml = r#"
[app]
os-linux = "~"
files = "tool.conf"
"#;
    let repo = TestGitRepo::new(remote_toml, &[("app/tool.conf", b"content\n")]);
    let url = parse_url(&repo.clone_url).unwrap();

    let malicious_overrides = [
        PathBuf::from("../outside"),
        PathBuf::from("a/../../b"),
        PathBuf::from("/etc"),
        PathBuf::from("/var/run"),
        sandbox.home_dir.join("../secret"),
        sandbox.home_dir.join(".config").join("dotler"),
        sandbox
            .home_dir
            .join(".config")
            .join("dotler")
            .join("state.db"),
        sandbox.home_dir.join(".git"),
        sandbox.home_dir.join("sub").join(".git"),
        sandbox.home_dir.join("var$foo"),
        sandbox.home_dir.join("var%foo"),
        sandbox.home_dir.join("var\\foo"),
    ];

    for bad_override in &malicious_overrides {
        let res = install_remote(
            &url,
            &["app".to_string()],
            Some(bad_override),
            None,
            &[],
            &sandbox.state_db,
            &lock,
        );

        assert!(
            res.is_err(),
            "Expected install_remote with path_override {:?} to fail security validation, but succeeded",
            bad_override
        );

        match res.unwrap_err() {
            EngineError::HardBlockedPath { .. }
            | EngineError::Config(ConfigError::HardBlockedPath { .. }) => {
                // Expected security violation
            }
            other => {
                panic!(
                    "Expected HardBlockedPath error for override {:?}, got: {:?}",
                    bad_override, other
                );
            }
        }
    }
}

#[test]
fn test_adversarial_fresh_file_repeated_install_uninstall_stress() {
    let sandbox = TestSandbox::new();
    let lock = sandbox.acquire_lock();

    let target_file = sandbox.home_dir.join("fresh_tool.conf");
    assert!(!target_file.exists());

    let remote_toml = r#"
[tool]
os-linux = "~"
files = "fresh_tool.conf"
"#;
    let repo = TestGitRepo::new(
        remote_toml,
        &[("tool/fresh_tool.conf", b"REMOTE_TOOL_CONTENT\n")],
    );
    let url = parse_url(&repo.clone_url).unwrap();

    // Perform 10 consecutive installs of fresh files
    for cycle in 1..=10 {
        let rep = install_remote(
            &url,
            &["tool".to_string()],
            Some(&sandbox.home_dir),
            None,
            &[],
            &sandbox.state_db,
            &lock,
        )
        .expect("install_remote fresh cycle");

        assert_eq!(rep.installed_files.len(), 1);
        assert_eq!(
            rep.backed_up_files.len(),
            0,
            "Cycle {cycle}: fresh file install must never create backup"
        );
        assert!(target_file.is_file());

        let record = sandbox
            .state_db
            .get_installed_file(&target_file.to_string_lossy())
            .unwrap()
            .unwrap();
        assert!(
            record.backup_path.is_none(),
            "Cycle {cycle}: backup_path must remain None"
        );
    }

    // Uninstall
    let uninst = uninstall_remote(&["tool".to_string()], &sandbox.state_db, &lock, false).unwrap();
    assert_eq!(uninst.removed_files.len(), 1);
    assert_eq!(uninst.restored_backups.len(), 0);
    assert!(
        !target_file.exists(),
        "Fresh file must be removed after uninstall"
    );

    // Second uninstall (idempotency)
    let uninst2 = uninstall_remote(&["tool".to_string()], &sandbox.state_db, &lock, false).unwrap();
    assert_eq!(uninst2.removed_files.len(), 0);
    assert_eq!(uninst2.restored_backups.len(), 0);
    assert!(!target_file.exists());
}

#[test]
fn test_adversarial_preexisting_file_repeated_install_uninstall_stress() {
    let sandbox = TestSandbox::new();
    let lock = sandbox.acquire_lock();

    let original_content = b"ORIGINAL_USER_CONFIG_V1\n";
    let target_file = sandbox.write_home_file("user_tool.conf", original_content);
    assert!(target_file.is_file());

    let remote_content = b"REMOTE_OVERWRITTEN_CONFIG\n";
    let remote_toml = r#"
[tool]
os-linux = "~"
files = "user_tool.conf"
"#;
    let repo = TestGitRepo::new(remote_toml, &[("tool/user_tool.conf", remote_content)]);
    let url = parse_url(&repo.clone_url).unwrap();

    let mut original_backup_path: Option<String> = None;

    // Perform 10 consecutive installs on pre-existing file
    for cycle in 1..=10 {
        let rep = install_remote(
            &url,
            &["tool".to_string()],
            Some(&sandbox.home_dir),
            None,
            &[],
            &sandbox.state_db,
            &lock,
        )
        .expect("install_remote pre-existing cycle");

        let record = sandbox
            .state_db
            .get_installed_file(&target_file.to_string_lossy())
            .unwrap()
            .unwrap();

        if cycle == 1 {
            assert_eq!(rep.backed_up_files.len(), 1);
            let bp = record.backup_path.expect("cycle 1 must have backup_path");
            // Verify backup content matches user original data
            let backup_bytes = fs::read(&bp).expect("read backup file");
            assert_eq!(backup_bytes, original_content);
            original_backup_path = Some(bp);
        } else {
            assert_eq!(
                rep.backed_up_files.len(),
                0,
                "Cycle {cycle}: subsequent install must not re-backup Dotler's deployed file"
            );
            assert_eq!(
                record.backup_path, original_backup_path,
                "Cycle {cycle}: backup_path must strictly preserve original backup"
            );
        }

        // Active file has remote content
        assert_eq!(fs::read(&target_file).unwrap(), remote_content);
    }

    // Now uninstall: MUST restore original content
    let uninst = uninstall_remote(&["tool".to_string()], &sandbox.state_db, &lock, false).unwrap();
    assert_eq!(uninst.restored_backups.len(), 1);
    assert_eq!(uninst.removed_files.len(), 0);

    // Target file restored to original content
    assert_eq!(fs::read(&target_file).unwrap(), original_content);

    // Backup file should be cleaned up
    assert!(!Path::new(&original_backup_path.unwrap()).exists());

    // DB record should be gone
    assert!(
        sandbox
            .state_db
            .get_installed_file(&target_file.to_string_lossy())
            .unwrap()
            .is_none()
    );
}

#[test]
fn test_adversarial_mixed_fresh_and_preexisting_stress() {
    let sandbox = TestSandbox::new();
    let lock = sandbox.acquire_lock();

    let pre_content = b"EXISTING_USER_FILE\n";
    let pre_file = sandbox.write_home_file("existing.conf", pre_content);
    let fresh_file = sandbox.home_dir.join("fresh.conf");
    assert!(!fresh_file.exists());

    let remote_toml = r#"
[mixed]
os-linux = "~"
files = """
existing.conf
fresh.conf
"""
"#;
    let repo = TestGitRepo::new(
        remote_toml,
        &[
            ("mixed/existing.conf", b"REMOTE_EXISTING\n"),
            ("mixed/fresh.conf", b"REMOTE_FRESH\n"),
        ],
    );
    let url = parse_url(&repo.clone_url).unwrap();

    // 5 install cycles
    for cycle in 1..=5 {
        let rep = install_remote(
            &url,
            &["mixed".to_string()],
            Some(&sandbox.home_dir),
            None,
            &[],
            &sandbox.state_db,
            &lock,
        )
        .unwrap();

        if cycle == 1 {
            assert_eq!(rep.backed_up_files.len(), 1);
        } else {
            assert_eq!(rep.backed_up_files.len(), 0);
        }

        let pre_rec = sandbox
            .state_db
            .get_installed_file(&pre_file.to_string_lossy())
            .unwrap()
            .unwrap();
        assert!(pre_rec.backup_path.is_some());

        let fresh_rec = sandbox
            .state_db
            .get_installed_file(&fresh_file.to_string_lossy())
            .unwrap()
            .unwrap();
        assert!(fresh_rec.backup_path.is_none());
    }

    // Uninstall
    let uninst = uninstall_remote(&["mixed".to_string()], &sandbox.state_db, &lock, false).unwrap();
    assert_eq!(uninst.restored_backups.len(), 1);
    assert_eq!(uninst.removed_files.len(), 1);

    // Verify existing was restored, fresh was deleted
    assert_eq!(fs::read(&pre_file).unwrap(), pre_content);
    assert!(!fresh_file.exists());
    assert_eq!(
        sandbox.state_db.list_installed_files(None).unwrap().len(),
        0
    );
}

#[test]
fn test_import_files_hash_match_skip_commits_sqlite_upsert_plain() {
    let sandbox = TestSandbox::new();
    let lock = sandbox.acquire_lock();

    let content = b"SYNC_FILE_CONTENT_TEST\n";
    let target_file = sandbox.write_home_file("test.conf", content);

    let repo_dir = sandbox.home_dir.join("repo");
    fs::create_dir_all(repo_dir.join("tool")).unwrap();
    let repo_file = repo_dir.join("tool").join("test.conf");
    fs::write(&repo_file, content).unwrap();

    let dotler_toml = r#"
[tool]
os-linux = "~"
files = "test.conf"
"#;
    let repo_config = RepoConfig::parse(dotler_toml).unwrap();

    let engine = SyncEngine::new(
        "default",
        &repo_dir,
        &repo_config,
        &sandbox.state_db,
        vec![],
        OsInfo::detect(),
        None,
    )
    .with_home_dir(&sandbox.home_dir);

    // Initial state: state_db has NO record for test.conf
    let before_record = sandbox
        .state_db
        .get_synced_file(&target_file.to_string_lossy())
        .unwrap();
    assert!(before_record.is_none());

    // Import files: file content matches repo, so plan status is Synced
    let plans = engine.plan(None, &lock).unwrap();
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].status, FileSyncStatus::Synced);

    let report = engine.import_files(&plans, &lock, false).unwrap();
    assert_eq!(report.skipped, 1);
    assert_eq!(report.processed, 0);

    // Invariant: state_db MUST now have committed the SyncedFileRecord!
    let after_record = sandbox
        .state_db
        .get_synced_file(&target_file.to_string_lossy())
        .unwrap();
    assert!(
        after_record.is_some(),
        "state_db must contain upserted synced_file even when disk write was skipped"
    );
    let rec = after_record.unwrap();
    assert_eq!(rec.relative_path, "test.conf");
    assert_eq!(rec.group_name, "tool");
    let expected_hash = blake3::hash(content).to_hex().to_string();
    assert_eq!(rec.file_hash, expected_hash);
}

#[test]
fn test_import_files_hash_match_skip_commits_sqlite_upsert_encrypted() {
    let sandbox = TestSandbox::new();
    let lock = sandbox.acquire_lock();

    let secret_content = b"SECRET_SYNC_TEST_VALUE\n";
    let target_file = sandbox.write_home_file("secret.env", secret_content);

    let repo_dir = sandbox.home_dir.join("repo");
    fs::create_dir_all(repo_dir.join("secure")).unwrap();

    let passphrase = SecretString::from("correct horse battery staple 12345".to_string());
    let (vault_cfg, vault_key, _mnemonic) = init_vault(&passphrase).unwrap();

    let dotler_toml = format!(
        r#"
[vault]
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[secure]
os-linux = "~"
files = "@secret.env"
"#,
        vault_cfg.vault_id, vault_cfg.password_slot, vault_cfg.recovery_slot
    );
    let repo_config = RepoConfig::parse(&dotler_toml).unwrap();

    let engine = SyncEngine::new(
        "default",
        &repo_dir,
        &repo_config,
        &sandbox.state_db,
        vec![],
        OsInfo::detect(),
        Some(&vault_key),
    )
    .with_home_dir(&sandbox.home_dir);

    // Step 1: Initial import will encrypt and write .enc file
    let plans1 = engine.plan(None, &lock).unwrap();
    assert_eq!(plans1.len(), 1);
    let report1 = engine.import_files(&plans1, &lock, false).unwrap();
    assert_eq!(report1.processed, 1);
    assert_eq!(report1.skipped, 0);

    // Step 2: Delete state db record to simulate missing/desynced sqlite ledger
    sandbox
        .state_db
        .remove_synced_file(&target_file.to_string_lossy())
        .unwrap();
    assert!(
        sandbox
            .state_db
            .get_synced_file(&target_file.to_string_lossy())
            .unwrap()
            .is_none()
    );

    // Step 3: Run import again. Content on disk matches plaintext inside .enc file
    // So can_skip evaluates to true (skipping re-encryption).
    let plans2 = engine.plan(None, &lock).unwrap();
    assert_eq!(plans2.len(), 1);
    let report2 = engine.import_files(&plans2, &lock, false).unwrap();
    assert_eq!(report2.skipped, 1);
    assert_eq!(report2.processed, 0);

    // Step 4: Verify that sqlite ledger was UPSERTED on skip!
    let restored_record = sandbox
        .state_db
        .get_synced_file(&target_file.to_string_lossy())
        .unwrap();
    assert!(
        restored_record.is_some(),
        "state_db must be restored/upserted during skipped re-encryption"
    );
    let rec = restored_record.unwrap();
    let expected_hash = blake3::hash(secret_content).to_hex().to_string();
    assert_eq!(rec.file_hash, expected_hash);
}

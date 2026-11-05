//! Adversarial challenge test suite for Remote Git Engine and WAL recovery.
//!
//! Tests:
//! 1. Payload Limit Boundary Testing (`list_remote` 1 MiB cap)
//! 2. Security & Path Traversal Attacks (`clone_repo` and `install_remote`)
//! 3. WAL Recovery & Backup Preservation Across Retries (`install_remote` & `uninstall_remote`)
//! 4. In-Memory Re-Keying and Snapshot Isolation

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;

use dotler::config::state::{DotlerLock, DotlerLockGuard, StateDb};
use dotler::crypto::vault::{EncryptedFile, init_vault};
use dotler::crypto::{ExposeSecret, SecretString};
use dotler::engine::EngineError;
use dotler::engine::remote::{
    REMOTE_TOML_FETCH_MAX_BYTES, STAGING_CLONE_PREFIX, clone_repo, install_remote, list_remote,
    parse_url, uninstall_remote,
};

pub struct ChallengeSandbox {
    pub root: TempDir,
    pub home_dir: PathBuf,
    pub config_dir: PathBuf,
    pub state_db: StateDb,
    pub lock_path: PathBuf,
}

impl Default for ChallengeSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeSandbox {
    pub fn new() -> Self {
        let root = tempfile::tempdir().expect("create challenge test tempdir");
        let home_dir = root.path().join("home");
        let config_dir = home_dir.join(".config").join("dotler");

        fs::create_dir_all(&config_dir).expect("create config dir");

        let db_path = config_dir.join("state.db");
        let state_db = StateDb::open(&db_path).expect("open state db");

        let lock_path = config_dir.join("dotler.lock");

        Self {
            root,
            home_dir,
            config_dir,
            state_db,
            lock_path,
        }
    }

    pub fn acquire_lock(&self) -> DotlerLockGuard {
        let lock = DotlerLock::new(self.lock_path.clone());
        lock.acquire(Duration::from_millis(5000), Duration::from_millis(50))
            .expect("acquire test lock")
    }

    pub fn write_home_file(&self, rel_path: &str, content: &[u8]) -> PathBuf {
        let full_path = self.home_dir.join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&full_path, content).unwrap();
        full_path
    }

    pub fn read_home_file(&self, rel_path: &str) -> Option<Vec<u8>> {
        let full_path = self.home_dir.join(rel_path);
        fs::read(full_path).ok()
    }
}

pub struct MockGitRepo {
    pub temp_dir: TempDir,
    pub bare_path: PathBuf,
    pub clone_url: String,
}

impl MockGitRepo {
    pub fn new(dotler_toml: &str, files: &[(&str, &[u8])]) -> Self {
        let temp_dir = tempfile::tempdir().expect("create mock git tempdir");
        let worktree = temp_dir.path().join("worktree");
        let bare_path = temp_dir.path().join("repo.git");

        fs::create_dir_all(&worktree).unwrap();

        let run = |args: &[&str], dir: &Path| {
            let status = Command::new("git")
                .args(args)
                .current_dir(dir)
                .status()
                .expect("execute git command");
            assert!(status.success(), "git {:?} failed", args);
        };

        run(&["init", "-b", "main"], &worktree);
        run(&["config", "user.name", "Challenger"], &worktree);
        run(
            &["config", "user.email", "challenger@dotler.dev"],
            &worktree,
        );

        fs::write(worktree.join("dotler.toml"), dotler_toml).unwrap();

        for (rel_path, content) in files {
            let full = worktree.join(rel_path);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(full, content).unwrap();
        }

        run(&["add", "."], &worktree);
        run(&["commit", "-m", "Initial commit"], &worktree);
        run(
            &[
                "clone",
                "--bare",
                worktree.to_str().unwrap(),
                bare_path.to_str().unwrap(),
            ],
            temp_dir.path(),
        );

        let clone_url = format!("file://{}", bare_path.display());
        Self {
            temp_dir,
            bare_path,
            clone_url,
        }
    }
}

// ============================================================================
// Suite 1: Payload Limit Boundary Testing (`list_remote`)
// ============================================================================

#[test]
fn test_list_remote_payload_exact_1mib_passes() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let base = "[shell]\nos-linux = \"~\"\nfiles = \"*.sh\"\n";
    let target_len = REMOTE_TOML_FETCH_MAX_BYTES; // 1,048,576 bytes
    assert!(target_len > base.len());

    let mut padded = String::with_capacity(target_len);
    padded.push_str(base);
    let needed = target_len - base.len();
    let comment_body = "#".repeat(needed.saturating_sub(1));
    padded.push_str(&comment_body);
    padded.push('\n');

    assert_eq!(padded.len(), target_len, "Payload must be exactly 1 MiB");

    let mock_repo = MockGitRepo::new(&padded, &[]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    let summary = list_remote(&url, None, &lock).expect("Exact 1 MiB payload must succeed");
    assert_eq!(summary.groups.len(), 1);
    assert_eq!(summary.groups[0].name, "shell");
}

#[test]
fn test_list_remote_payload_1mib_plus_one_byte_aborts() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let base = "[shell]\nos-linux = \"~\"\nfiles = \"*.sh\"\n";
    let target_len = REMOTE_TOML_FETCH_MAX_BYTES + 1; // 1,048,577 bytes

    let mut padded = String::with_capacity(target_len);
    padded.push_str(base);
    let needed = target_len - base.len();
    let comment_body = "#".repeat(needed.saturating_sub(1));
    padded.push_str(&comment_body);
    padded.push('\n');

    assert_eq!(
        padded.len(),
        target_len,
        "Payload must be exactly 1 MiB + 1 byte"
    );

    let mock_repo = MockGitRepo::new(&padded, &[]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    let err =
        list_remote(&url, None, &lock).expect_err("1 MiB + 1 byte must fail with PayloadExceeded");
    match err {
        EngineError::PayloadExceeded {
            size_bytes,
            limit_bytes,
        } => {
            assert_eq!(size_bytes, 1_048_577);
            assert_eq!(limit_bytes, REMOTE_TOML_FETCH_MAX_BYTES);
            assert_eq!(
                err.exit_code(),
                2,
                "PayloadExceeded must map to exit code 2"
            );
            assert_eq!(err.error_code(), "PAYLOAD_EXCEEDED");
        }
        other => panic!("Expected PayloadExceeded, got: {:?}", other),
    }
}

// ============================================================================
// Suite 2: Security & Path Traversal Attacks (`clone_repo` and `install_remote`)
// ============================================================================

#[test]
fn test_clone_repo_path_traversal_dot_dot_aborts_exit_code_3() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let malicious_toml = r#"
[attack]
os-linux = "~/../../etc"
files = "passwd"
"#;
    let mock_repo = MockGitRepo::new(malicious_toml, &[("attack/passwd", b"evil")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();
    let dest = sandbox.root.path().join("cloned_attack");

    let err = clone_repo(&url, &[], None, &dest, None, None, None, &lock)
        .expect_err("Path traversal must be rejected");

    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");
    assert!(!dest.exists());

    let parent = dest.parent().unwrap();
    let lingering_staging = fs::read_dir(parent)
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(STAGING_CLONE_PREFIX)
        });
    assert!(!lingering_staging, "Staging directory must be cleaned up");
}

#[test]
fn test_clone_repo_absolute_path_aborts_exit_code_3() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let malicious_toml = r#"
[attack]
os-linux = "/etc/passwd"
files = "passwd"
"#;
    let mock_repo = MockGitRepo::new(malicious_toml, &[("attack/passwd", b"evil")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();
    let dest = sandbox.root.path().join("cloned_attack");

    let err = clone_repo(&url, &[], None, &dest, None, None, None, &lock)
        .expect_err("Absolute path must be rejected");

    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");
    assert!(!dest.exists());
}

#[test]
fn test_clone_repo_target_git_directory_aborts_exit_code_3() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let malicious_toml = r#"
[attack]
os-linux = "~/.git/hooks"
files = "pre-commit"
"#;
    let mock_repo = MockGitRepo::new(malicious_toml, &[("attack/pre-commit", b"evil")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();
    let dest = sandbox.root.path().join("cloned_attack");

    let err = clone_repo(&url, &[], None, &dest, None, None, None, &lock)
        .expect_err(".git target must be rejected");

    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");
    assert!(!dest.exists());
}

#[test]
fn test_clone_repo_target_internal_dotler_config_aborts_exit_code_3() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let malicious_toml = r#"
[attack]
os-linux = "~/.config/dotler/evil"
files = "evil.db"
"#;
    let mock_repo = MockGitRepo::new(malicious_toml, &[("attack/evil.db", b"evil")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();
    let dest = sandbox.root.path().join("cloned_attack");

    let err = clone_repo(&url, &[], None, &dest, None, None, None, &lock)
        .expect_err("~/.config/dotler target must be rejected");

    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");
    assert!(!dest.exists());
}

#[test]
fn test_clone_repo_selection_pattern_traversal_aborts_exit_code_3() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let malicious_toml = r#"
[attack]
os-linux = "~"
files = "../../../etc/shadow"
"#;
    let mock_repo = MockGitRepo::new(malicious_toml, &[]);
    let url = parse_url(&mock_repo.clone_url).unwrap();
    let dest = sandbox.root.path().join("cloned_attack");

    let err = clone_repo(&url, &[], None, &dest, None, None, None, &lock)
        .expect_err("Selection rule traversal must be rejected");

    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");
    assert!(!dest.exists());
}

#[test]
fn test_clone_repo_rekeying_across_different_vaults() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    // Vault Remote
    let remote_secret = SecretString::new("remote-vault-pass-secret".to_string());
    let (remote_vault_cfg, remote_vault_key, _) = init_vault(&remote_secret).unwrap();

    // Vault Local
    let local_secret = SecretString::new("local-vault-pass-secret".to_string());
    let (_local_vault_cfg, local_vault_key, _) = init_vault(&local_secret).unwrap();

    assert_ne!(remote_vault_key.vault_id(), local_vault_key.vault_id());

    let secret_dotfile = b"PRIVATE_API_TOKEN_XYZ123456789";
    let encrypted_remote = remote_vault_key.encrypt_file(secret_dotfile).unwrap();

    let remote_toml = format!(
        r#"
[vault]
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[secure]
os-linux = "~/.config/app"
files = "@token.enc"
"#,
        remote_vault_cfg.vault_id, remote_vault_cfg.password_slot, remote_vault_cfg.recovery_slot,
    );

    let mock_repo = MockGitRepo::new(
        &remote_toml,
        &[("secure/token.enc", &encrypted_remote.to_bytes())],
    );
    let url = parse_url(&mock_repo.clone_url).unwrap();
    let dest = sandbox.root.path().join("cloned_rekey");

    let report = clone_repo(
        &url,
        &[],
        None,
        &dest,
        None,
        Some(&remote_vault_key),
        Some(&local_vault_key),
        &lock,
    )
    .expect("Clone with in-memory Re-Keying must succeed");

    assert_eq!(report.destination, dest);
    let rekeyed_file_path = dest.join("secure/token.enc");
    assert!(rekeyed_file_path.is_file());

    let rekeyed_bytes = fs::read(&rekeyed_file_path).unwrap();
    let enc_file = EncryptedFile::from_bytes(&rekeyed_bytes).unwrap();

    // File should now be tied to local vault ID
    assert_eq!(enc_file.vault_id, local_vault_key.vault_id_bytes());

    // Remote key should fail to decrypt
    assert!(remote_vault_key.decrypt_file(&enc_file).is_err());

    // Local key should decrypt successfully to original plaintext
    let decrypted = local_vault_key.decrypt_file(&enc_file).unwrap();
    assert_eq!(decrypted.expose_secret(), secret_dotfile);
}

#[test]
fn test_install_remote_path_traversal_aborts_exit_code_3_and_cleans_staging() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let malicious_toml = r#"
[attack]
os-linux = "~/../../etc"
files = "shadow"
"#;
    let mock_repo = MockGitRepo::new(malicious_toml, &[("attack/shadow", b"evil")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    let err = install_remote(
        &url,
        &["attack".to_string()],
        None,
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .expect_err("install_remote must reject path traversal");

    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");
    assert_eq!(
        sandbox.state_db.list_installed_files(None).unwrap().len(),
        0
    );
}

#[test]
fn test_install_remote_absolute_path_aborts_exit_code_3() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let malicious_toml = r#"
[attack]
os-linux = "/var/log/attack"
files = "attack.log"
"#;
    let mock_repo = MockGitRepo::new(malicious_toml, &[("attack/attack.log", b"evil")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    let err = install_remote(
        &url,
        &["attack".to_string()],
        None,
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .expect_err("install_remote must reject absolute path");

    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");
}

#[test]
fn test_install_remote_dotler_config_target_aborts_exit_code_3() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let malicious_toml = r#"
[attack]
os-linux = "~/.config/dotler"
files = "state.db"
"#;
    let mock_repo = MockGitRepo::new(malicious_toml, &[("attack/state.db", b"evil")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    let err = install_remote(
        &url,
        &["attack".to_string()],
        None,
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .expect_err("install_remote must reject ~/.config/dotler target");

    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");
}

// ============================================================================
// Suite 3: WAL Recovery, Backup Preservation & Uninstall Idempotency
// ============================================================================

#[test]
fn test_install_remote_repeated_retries_preserve_original_backup_strictly() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let original_bytes = b"ORIGINAL_USER_CONTENT_V0\n";
    sandbox.write_home_file("my_tool.conf", original_bytes);

    let remote_toml = r#"
[tool]
os-linux = "~"
files = "my_tool.conf"
"#;
    let mock_repo = MockGitRepo::new(
        remote_toml,
        &[("tool/my_tool.conf", b"REMOTE_DEPLOYMENT_V1\n")],
    );
    let url = parse_url(&mock_repo.clone_url).unwrap();

    // 1st Install
    let rep1 = install_remote(
        &url,
        &["tool".to_string()],
        Some(&sandbox.home_dir),
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .unwrap();

    assert_eq!(rep1.installed_files.len(), 1);
    assert_eq!(rep1.backed_up_files.len(), 1);
    let original_backup_path = rep1.backed_up_files[0].clone();

    // Verify backup contains original content
    assert_eq!(fs::read(&original_backup_path).unwrap(), original_bytes);

    // 2nd Install (simulated retry / crash recovery rerun)
    let rep2 = install_remote(
        &url,
        &["tool".to_string()],
        Some(&sandbox.home_dir),
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .unwrap();

    // Must NOT create a secondary backup over the already deployed file
    assert_eq!(rep2.backed_up_files.len(), 0);

    // The recorded backup path must still be the initial one, and content unchanged
    let recorded_record = sandbox
        .state_db
        .get_installed_file(&sandbox.home_dir.join("my_tool.conf").to_string_lossy())
        .unwrap()
        .expect("Installed record must exist");
    assert_eq!(
        recorded_record.backup_path.as_ref().map(PathBuf::from),
        Some(original_backup_path.clone())
    );
    assert_eq!(fs::read(&original_backup_path).unwrap(), original_bytes);

    // 3rd Install (simulate repeated execution)
    let rep3 = install_remote(
        &url,
        &["tool".to_string()],
        Some(&sandbox.home_dir),
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .unwrap();
    assert_eq!(rep3.backed_up_files.len(), 0);
    assert_eq!(fs::read(&original_backup_path).unwrap(), original_bytes);

    // Uninstall restores original content byte-for-byte
    let uninst = uninstall_remote(&["tool".to_string()], &sandbox.state_db, &lock, false).unwrap();
    assert_eq!(uninst.restored_backups.len(), 1);
    assert_eq!(
        sandbox.read_home_file("my_tool.conf").unwrap(),
        original_bytes
    );

    // Backup file itself should be cleaned up
    assert!(!original_backup_path.exists());
    assert_eq!(
        sandbox.state_db.list_installed_files(None).unwrap().len(),
        0
    );
}

#[test]
fn test_install_remote_fresh_file_repeated_install_and_uninstall() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    // User does NOT have new_app.conf beforehand
    let target_file = sandbox.home_dir.join("new_app.conf");
    assert!(!target_file.exists());

    let remote_toml = r#"
[app]
os-linux = "~"
files = "new_app.conf"
"#;
    let mock_repo = MockGitRepo::new(
        remote_toml,
        &[("app/new_app.conf", b"APP_REMOTE_CONTENT\n")],
    );
    let url = parse_url(&mock_repo.clone_url).unwrap();

    // 1st Install
    let rep1 = install_remote(
        &url,
        &["app".to_string()],
        Some(&sandbox.home_dir),
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .unwrap();

    assert_eq!(rep1.installed_files.len(), 1);
    assert_eq!(rep1.backed_up_files.len(), 0, "Fresh file has no backup");
    assert!(target_file.is_file());

    let record1 = sandbox
        .state_db
        .get_installed_file(&target_file.to_string_lossy())
        .unwrap()
        .unwrap();
    assert!(record1.backup_path.is_none());

    // 2nd Install (re-run on fresh file)
    let rep2 = install_remote(
        &url,
        &["app".to_string()],
        Some(&sandbox.home_dir),
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .unwrap();

    // Even across repeated installs of fresh files, backed_up_files must remain 0
    // and backup_path must remain None because the file was never pre-existing user data!
    assert_eq!(
        rep2.backed_up_files.len(),
        0,
        "Repeated install of fresh file must not create a backup"
    );

    let record2 = sandbox
        .state_db
        .get_installed_file(&target_file.to_string_lossy())
        .unwrap()
        .unwrap();
    assert!(
        record2.backup_path.is_none(),
        "backup_path must remain None across repeated installs of fresh files, but got: {:?}",
        record2.backup_path
    );

    // Now test uninstall
    let uninst = uninstall_remote(&["app".to_string()], &sandbox.state_db, &lock, false).unwrap();

    // For a file that never existed before dotler, uninstall MUST remove it from disk!
    assert!(
        !target_file.exists(),
        "File that did not exist prior to install must be deleted upon uninstall"
    );
    assert_eq!(uninst.removed_files.len(), 1);
    assert_eq!(uninst.restored_backups.len(), 0);
    assert_eq!(
        sandbox.state_db.list_installed_files(None).unwrap().len(),
        0
    );
}

#[test]
fn test_uninstall_remote_idempotency_multi_run() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let remote_toml = r#"
[shell]
os-linux = "~"
files = "script.sh"
"#;
    let mock_repo = MockGitRepo::new(remote_toml, &[("shell/script.sh", b"echo hi\n")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    install_remote(
        &url,
        &["shell".to_string()],
        Some(&sandbox.home_dir),
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .unwrap();

    // 1st Uninstall
    let uninst1 =
        uninstall_remote(&["shell".to_string()], &sandbox.state_db, &lock, false).unwrap();
    assert_eq!(uninst1.removed_files.len(), 1);

    // 2nd Uninstall (idempotency check)
    let uninst2 =
        uninstall_remote(&["shell".to_string()], &sandbox.state_db, &lock, false).unwrap();
    assert_eq!(uninst2.removed_files.len(), 0);
    assert_eq!(uninst2.restored_backups.len(), 0);

    // 3rd Uninstall (all groups empty)
    let uninst3 = uninstall_remote(&[], &sandbox.state_db, &lock, false).unwrap();
    assert_eq!(uninst3.removed_files.len(), 0);
    assert_eq!(uninst3.restored_backups.len(), 0);
}

#[test]
fn test_uninstall_remote_dry_run_leaves_filesystem_and_db_intact() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let original = b"ORIGINAL_BEFORE_INSTALL\n";
    sandbox.write_home_file("editor.rc", original);

    let remote_toml = r#"
[editor]
os-linux = "~"
files = "editor.rc"
"#;
    let mock_repo = MockGitRepo::new(remote_toml, &[("editor/editor.rc", b"REMOTE_CONFIG\n")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    install_remote(
        &url,
        &["editor".to_string()],
        Some(&sandbox.home_dir),
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .unwrap();

    // Dry-run uninstall
    let dry_rep =
        uninstall_remote(&["editor".to_string()], &sandbox.state_db, &lock, true).unwrap();
    assert_eq!(dry_rep.restored_backups.len(), 1);

    // Filesystem still has deployed remote content
    assert_eq!(
        sandbox.read_home_file("editor.rc").unwrap(),
        b"REMOTE_CONFIG\n"
    );

    // DB record still exists
    let records = sandbox.state_db.list_installed_files(None).unwrap();
    assert_eq!(records.len(), 1);

    // Now execute actual uninstall
    let real_rep =
        uninstall_remote(&["editor".to_string()], &sandbox.state_db, &lock, false).unwrap();
    assert_eq!(real_rep.restored_backups.len(), 1);
    assert_eq!(sandbox.read_home_file("editor.rc").unwrap(), original);
    assert_eq!(
        sandbox.state_db.list_installed_files(None).unwrap().len(),
        0
    );
}

#[test]
fn test_clone_repo_non_empty_dest_aborts() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let remote_toml = r#"
[shell]
os-linux = "~"
files = "*.sh"
"#;
    let mock_repo = MockGitRepo::new(remote_toml, &[("shell/test.sh", b"echo 1")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();
    let dest = sandbox.root.path().join("existing_non_empty");
    fs::create_dir_all(&dest).unwrap();
    fs::write(dest.join("blocker.txt"), b"already exists").unwrap();

    let err = clone_repo(&url, &[], None, &dest, None, None, None, &lock)
        .expect_err("Clone to non-empty destination must fail");

    match err {
        EngineError::GitError { operation, .. } => assert_eq!(operation, "clone"),
        other => panic!("Expected GitError, got: {:?}", other),
    }
}

#[test]
fn test_clone_repo_unknown_selector_aborts() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let remote_toml = r#"
[shell]
os-linux = "~"
files = "*.sh"
"#;
    let mock_repo = MockGitRepo::new(remote_toml, &[("shell/test.sh", b"echo 1")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();
    let dest = sandbox.root.path().join("cloned_repo");

    let selectors = vec![dotler::engine::remote::GroupSelector::parse("nonexistent")];
    let err = clone_repo(&url, &selectors, None, &dest, None, None, None, &lock)
        .expect_err("Unknown group selector must fail");

    match err {
        EngineError::GroupNotFound { group, .. } => assert_eq!(group, "nonexistent"),
        other => panic!("Expected GroupNotFound, got: {:?}", other),
    }
    assert!(!dest.exists());
}

#[test]
fn test_install_remote_unknown_group_aborts() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let remote_toml = r#"
[shell]
os-linux = "~"
files = "*.sh"
"#;
    let mock_repo = MockGitRepo::new(remote_toml, &[("shell/test.sh", b"echo 1")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    let err = install_remote(
        &url,
        &["ghost_group".to_string()],
        None,
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .expect_err("install_remote with unknown group must fail");

    match err {
        EngineError::GroupNotFound { group, .. } => assert_eq!(group, "ghost_group"),
        other => panic!("Expected GroupNotFound, got: {:?}", other),
    }
}

#[test]
fn test_install_remote_respects_exclusion_rules() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let remote_toml = r#"
[pkg]
os-linux = "~"
files = """
*
!ignored.txt
"""
"#;
    let mock_repo = MockGitRepo::new(
        remote_toml,
        &[
            ("pkg/included.txt", b"INCLUDED"),
            ("pkg/ignored.txt", b"IGNORED"),
        ],
    );
    let url = parse_url(&mock_repo.clone_url).unwrap();

    let rep = install_remote(
        &url,
        &["pkg".to_string()],
        Some(&sandbox.home_dir),
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .unwrap();

    assert_eq!(rep.installed_files.len(), 1);
    assert!(sandbox.home_dir.join("included.txt").is_file());
    assert!(
        !sandbox.home_dir.join("ignored.txt").exists(),
        "Excluded file must not be installed"
    );
}

#[test]
fn test_list_remote_non_utf8_dotler_toml_aborts() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    // Invalid UTF-8 bytes: 0xFF, 0xFE
    let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
    let temp_dir = tempfile::tempdir().unwrap();
    let worktree = temp_dir.path().join("worktree");
    let bare_path = temp_dir.path().join("repo.git");
    fs::create_dir_all(&worktree).unwrap();

    let run = |args: &[&str], dir: &Path| {
        let status = Command::new("git")
            .args(args)
            .current_dir(dir)
            .status()
            .expect("execute git command");
        assert!(status.success(), "git {:?} failed", args);
    };

    run(&["init", "-b", "main"], &worktree);
    run(&["config", "user.name", "Challenger"], &worktree);
    run(
        &["config", "user.email", "challenger@dotler.dev"],
        &worktree,
    );

    fs::write(worktree.join("dotler.toml"), &invalid_utf8).unwrap();
    run(&["add", "."], &worktree);
    run(&["commit", "-m", "Non-utf8 commit"], &worktree);
    run(
        &[
            "clone",
            "--bare",
            worktree.to_str().unwrap(),
            bare_path.to_str().unwrap(),
        ],
        temp_dir.path(),
    );

    let clone_url = format!("file://{}", bare_path.display());
    let url = parse_url(&clone_url).unwrap();

    let err = list_remote(&url, None, &lock).expect_err("Non-UTF8 dotler.toml must fail");
    match err {
        EngineError::GitError { operation, message } => {
            assert_eq!(operation, "fetch");
            assert!(message.contains("UTF-8"));
        }
        other => panic!("Expected GitError with UTF-8 failure, got: {:?}", other),
    }
}

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use dotler::config::repo::{OsInfo, RepoConfig, VaultConfig};
use dotler::config::state::{
    DotlerLock, DotlerLockGuard, InstalledFileRecord, StateDb, SyncedFileRecord,
};
use dotler::crypto::keyring::OsKeyring;
use dotler::crypto::vault::{EncryptedFile, VaultKey, init_vault};
use dotler::engine::EngineError;
use dotler::engine::remote::{
    REMOTE_TOML_FETCH_MAX_BYTES, clone_repo, install_remote, list_remote, parse_url,
    uninstall_remote,
};
use dotler::engine::sync::{FileSyncStatus, SyncEngine, TidyOrphanPolicy};
use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;

#[allow(dead_code)]
static TEST_KEYRING_LOCK: Mutex<()> = Mutex::new(());

#[allow(dead_code)]
struct TestKeyringGuard<'a> {
    _lock: std::sync::MutexGuard<'a, ()>,
}

#[allow(dead_code)]
impl<'a> TestKeyringGuard<'a> {
    fn new() -> Self {
        let lock = TEST_KEYRING_LOCK.lock().unwrap();
        OsKeyring::enable_mock();
        OsKeyring::clear_mock();
        Self { _lock: lock }
    }
}

#[allow(dead_code)]
impl<'a> Drop for TestKeyringGuard<'a> {
    fn drop(&mut self) {
        OsKeyring::clear_mock();
        OsKeyring::disable_mock();
    }
}

pub struct SyncTestSandbox {
    pub root: TempDir,
    pub home_dir: PathBuf,
    pub dotler_dir: PathBuf,
    pub repo_dir: PathBuf,
    pub backups_dir: PathBuf,
    pub state_db: StateDb,
    pub lock_path: PathBuf,
}

impl Default for SyncTestSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncTestSandbox {
    pub fn new() -> Self {
        let root = tempfile::tempdir().expect("create sandbox tempdir");
        let root_path = root.path();

        let home_dir = root_path.join("home");
        let dotler_dir = home_dir.join(".config").join("dotler");
        let repo_dir = root_path.join("dotfiles");
        let backups_dir = dotler_dir.join("backups");

        fs::create_dir_all(&home_dir).unwrap();
        fs::create_dir_all(&dotler_dir).unwrap();
        fs::create_dir_all(&repo_dir).unwrap();
        fs::create_dir_all(&backups_dir).unwrap();

        let db_path = dotler_dir.join("state.db");
        let state_db = StateDb::open(&db_path).expect("open state.db");
        let lock_path = dotler_dir.join("dotler.lock");

        Self {
            root,
            home_dir,
            dotler_dir,
            repo_dir,
            backups_dir,
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

    pub fn write_repo_file(&self, rel_path: &str, content: &[u8]) -> PathBuf {
        let full_path = self.repo_dir.join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&full_path, content).unwrap();
        full_path
    }

    pub fn read_repo_file(&self, rel_path: &str) -> Option<Vec<u8>> {
        let full_path = self.repo_dir.join(rel_path);
        fs::read(full_path).ok()
    }

    pub fn write_dotler_toml(&self, toml_str: &str) {
        let path = self.repo_dir.join("dotler.toml");
        fs::write(path, toml_str).unwrap();
    }

    pub fn create_vault(&self, password: &str) -> (VaultConfig, VaultKey) {
        let secret = SecretString::new(password.to_string());
        let (config, key, _) = init_vault(&secret).unwrap();
        (config, key)
    }

    pub fn sync_engine<'a>(
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

pub struct MockBareRepo {
    pub temp_dir: TempDir,
    pub bare_path: PathBuf,
    pub clone_url: String,
}

impl MockBareRepo {
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
        run(&["config", "user.name", "Dotler Test"], &worktree);
        run(&["config", "user.email", "test@dotler.dev"], &worktree);

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
// Domain A: 3-Way Hash Reconciliation & Planning (`plan`)
// ============================================================================

#[test]
fn test_plan_all_synced_happy_path() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-linux = "~"
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
os-linux = "~"
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
os-linux = "~"
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
os-linux = "~"
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
os-linux = "~"
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
[vault]
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[secret]
os-linux = "~"
files = "secret.txt encrypt"
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
os-linux = "~"
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
os-linux = "~"
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
os-linux = "~"
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
os-linux = "~"
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
os-linux = "~"
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
[vault]
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[secret]
os-linux = "~"
files = "secret.txt encrypt"
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
os-linux = "~"
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

// ============================================================================
// Domain C: Deterministic Import & Hash Skipping (`import_files`)
// ============================================================================

#[test]
fn test_import_fresh_files_to_repo_atomic_staging() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-linux = "~"
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
[vault]
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[secret]
os-linux = "~"
files = "secret.txt encrypt"
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
[vault]
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[secret]
os-linux = "~"
files = "secret.txt encrypt"
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
os-linux = "~"
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
[vault]
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[secret]
os-linux = "~"
files = "secret.txt encrypt"
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
[vault]
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[secret]
os-linux = "~"
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
os-linux = "~"
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
fn test_tidy_orphan_rm_policy_deletes_os_file() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let toml = r#"
[shell]
os-linux = "~"
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
        .tidy(None, &lock, TidyOrphanPolicy::RemoveFromOs, false)
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
os-linux = "~"
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
        .tidy(None, &lock, TidyOrphanPolicy::RemoveFromOs, false)
        .unwrap();

    let installed = sandbox
        .state_db
        .get_installed_file("/dummy/target")
        .unwrap();
    assert!(installed.is_some());
}

// ============================================================================
// Domain E: Remote Git Clone & Security Staging (`clone_repo` & `list_remote`)
// ============================================================================

#[test]
fn test_git_url_shorthand_expansion() {
    assert_eq!(
        parse_url("gh:user/repo").unwrap().clone_url,
        "https://github.com/user/repo.git"
    );
    assert_eq!(
        parse_url("gl:team/sub/repo").unwrap().clone_url,
        "https://gitlab.com/team/sub/repo.git"
    );
    assert_eq!(
        parse_url("cb:owner/dotfiles").unwrap().clone_url,
        "https://codeberg.org/owner/dotfiles.git"
    );
    assert_eq!(
        parse_url("srht:~user/dotfiles").unwrap().clone_url,
        "https://git.sr.ht/~user/dotfiles"
    );
    assert_eq!(
        parse_url("bb:org/repo").unwrap().clone_url,
        "https://bitbucket.org/org/repo.git"
    );

    assert!(parse_url("").is_err());
    assert!(parse_url("invalid-scheme://foo").is_err());
    assert!(parse_url("gh:").is_err());
    assert!(parse_url("gh:/").is_err());
    assert!(parse_url("gl:").is_err());
    assert!(parse_url("gl:/").is_err());
    assert!(parse_url("cb:").is_err());
    assert!(parse_url("srht:").is_err());
    assert!(parse_url("bb:").is_err());
}

#[test]
fn test_git_ls_shallow_inspection_against_mock_bare_repo() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let remote_toml = r#"
[shell]
os-linux = "~"
files = "*.sh"

[nvim]
os-linux = "~/.config/nvim"
files = "init.lua"
"#;
    let mock_repo = MockBareRepo::new(remote_toml, &[("shell/test.sh", b"echo hi\n")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    let summary = list_remote(&url, None, &lock).unwrap();
    assert_eq!(summary.groups.len(), 2);
    let names: Vec<String> = summary.groups.into_iter().map(|g| g.name).collect();
    assert!(names.contains(&"shell".to_string()));
    assert!(names.contains(&"nvim".to_string()));
}

#[test]
fn test_git_ls_payload_cap_exceeded() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let large_comment = "#".repeat(REMOTE_TOML_FETCH_MAX_BYTES + 100);
    let remote_toml = format!(
        r#"
[shell]
os-linux = "~"
files = "*.sh"
{}
"#,
        large_comment
    );
    let mock_repo = MockBareRepo::new(&remote_toml, &[]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    let err = list_remote(&url, None, &lock).unwrap_err();
    match err {
        EngineError::PayloadExceeded {
            size_bytes,
            limit_bytes,
        } => {
            assert!(size_bytes > REMOTE_TOML_FETCH_MAX_BYTES);
            assert_eq!(limit_bytes, REMOTE_TOML_FETCH_MAX_BYTES);
        }
        _ => panic!("Expected PayloadExceeded, got: {:?}", err),
    }
}

#[test]
fn test_git_clone_staging_isolation_and_atomic_promotion() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let remote_toml = r#"
[shell]
os-linux = "~"
files = "*.sh"
"#;
    let mock_repo = MockBareRepo::new(remote_toml, &[("shell/hello.sh", b"echo hello\n")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    let target_dest = sandbox.root.path().join("cloned_repo");
    let report = clone_repo(&url, &[], None, &target_dest, None, None, None, &lock).unwrap();

    assert_eq!(report.destination, target_dest);
    assert!(target_dest.join("dotler.toml").is_file());
    assert!(target_dest.join("shell/hello.sh").is_file());
}

#[test]
fn test_git_clone_security_hard_block_cleans_staging() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let malicious_toml = r#"
[malicious]
os-linux = "~/../../etc"
files = "passwd"
"#;
    let mock_repo = MockBareRepo::new(malicious_toml, &[("malicious/passwd", b"root:x:0:0\n")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    let target_dest = sandbox.root.path().join("should_not_exist");
    let err = clone_repo(&url, &[], None, &target_dest, None, None, None, &lock).unwrap_err();

    assert_eq!(err.exit_code(), 3);
    assert!(!target_dest.exists());
}

// ============================================================================
// Domain F: WAL Remote Install & Uninstall Rollback (`install_remote` & `uninstall_remote`)
// ============================================================================

#[test]
fn test_git_install_wal_snapshot_and_deploy_cycle() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let original_content = b"ORIGINAL_BASHRC\n";
    sandbox.write_home_file(".bashrc", original_content);

    let remote_toml = r#"
[shell]
os-linux = "~"
files = ".bashrc"
"#;
    let remote_content = b"REMOTE_DEPLOYED_BASHRC\n";
    let mock_repo = MockBareRepo::new(remote_toml, &[("shell/.bashrc", remote_content)]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    let install_rep = install_remote(
        &url,
        &["shell".to_string()],
        Some(&sandbox.home_dir),
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .unwrap();

    assert_eq!(install_rep.installed_files.len(), 1);
    assert_eq!(install_rep.backed_up_files.len(), 1);

    // Deployed content matches remote
    assert_eq!(sandbox.read_home_file(".bashrc").unwrap(), remote_content);

    // Uninstall restores original content
    let uninstall_rep =
        uninstall_remote(&["shell".to_string()], &sandbox.state_db, &lock, false).unwrap();

    assert_eq!(uninstall_rep.restored_backups.len(), 1);
    assert_eq!(sandbox.read_home_file(".bashrc").unwrap(), original_content);

    // DB record should be removed
    let records = sandbox
        .state_db
        .list_installed_files(Some(&url.clone_url))
        .unwrap();
    assert_eq!(records.len(), 0);
}

#[test]
fn test_git_install_crash_retry_preserves_original_backup() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let original_content = b"VERY_ORIGINAL_FILE\n";
    sandbox.write_home_file("config.json", original_content);

    let remote_toml = r#"
[app]
os-linux = "~"
files = "config.json"
"#;
    let mock_repo = MockBareRepo::new(remote_toml, &[("app/config.json", b"REMOTE_V1\n")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    // First install
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
    let original_backup_path = rep1.backed_up_files[0].clone();

    // Simulate second install (retry / re-run)
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

    // The second install must not create a new backup over the already deployed file
    assert_eq!(rep2.backed_up_files.len(), 0);

    // The recorded backup path still points to the very original content
    let backup_data = fs::read(&original_backup_path).unwrap();
    assert_eq!(backup_data, original_content);
}

#[test]
fn test_git_install_and_uninstall_preserves_synced_files_table() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    // Track a synced file
    sandbox
        .state_db
        .upsert_synced_file(&SyncedFileRecord {
            target_path: "/custom/synced_target".to_string(),
            repo_label: "local_repo".to_string(),
            group_name: "local_group".to_string(),
            relative_path: "synced.txt".to_string(),
            file_hash: "synced_hash".to_string(),
            updated_at: 5000,
        })
        .unwrap();

    let remote_toml = r#"
[tools]
os-linux = "~"
files = "tool.sh"
"#;
    let mock_repo = MockBareRepo::new(remote_toml, &[("tools/tool.sh", b"tool\n")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    install_remote(
        &url,
        &["tools".to_string()],
        Some(&sandbox.home_dir),
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .unwrap();

    uninstall_remote(&["tools".to_string()], &sandbox.state_db, &lock, false).unwrap();

    // Synced file record must remain 100% intact
    let synced = sandbox
        .state_db
        .get_synced_file("/custom/synced_target")
        .unwrap();
    assert!(synced.is_some());
    assert_eq!(synced.unwrap().repo_label, "local_repo");
}

#[test]
fn test_install_remote_path_override_security_rejection() {
    let sandbox = SyncTestSandbox::new();
    let lock = sandbox.acquire_lock();

    let remote_toml = r#"
[tools]
os-linux = "~"
files = "tool.sh"
"#;
    let mock_repo = MockBareRepo::new(remote_toml, &[("tools/tool.sh", b"tool\n")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    // 1. Prohibited directory traversal
    let bad_override = sandbox.home_dir.join("../traversal");
    let err = install_remote(
        &url,
        &["tools".to_string()],
        Some(&bad_override),
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");

    // 2. Prohibited internal .config/dotler target
    let err = install_remote(
        &url,
        &["tools".to_string()],
        Some(&sandbox.dotler_dir),
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");
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
os-linux = "~"
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
        "[shell]\nos-linux = \"~\"\nfiles = \"*\"\n",
    )
    .unwrap();
    fs::write(internal_repo.join("SKILL.md"), "# Dotler\n").unwrap();

    let toml = r#"
[shell]
os-linux = "~"
os-macos = "~"
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

#[test]
fn test_tidy_single_and_multi_group_filters_isolate_orphans() {
    let sb = SyncTestSandbox::new();
    let lock = sb.acquire_lock();

    let dir_a = sb.home_dir.join("grp_a");
    let dir_b = sb.home_dir.join("grp_b");
    let dir_c = sb.home_dir.join("grp_c");
    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_b).unwrap();
    fs::create_dir_all(&dir_c).unwrap();

    fs::write(dir_a.join("keep_a.conf"), "a_keep").unwrap();
    fs::write(dir_a.join("orphan_a.conf"), "a_orphan").unwrap();
    fs::write(dir_b.join("orphan_b.conf"), "b_orphan").unwrap();
    fs::write(dir_c.join("orphan_c.conf"), "c_orphan").unwrap();

    let initial_toml = r#"[grp_a]
os-linux = "~/grp_a"
os-macos = "~/grp_a"
os-windows = "~/grp_a"
files = "*"

[grp_b]
os-linux = "~/grp_b"
os-macos = "~/grp_b"
os-windows = "~/grp_b"
files = "*"

[grp_c]
os-linux = "~/grp_c"
os-macos = "~/grp_c"
os-windows = "~/grp_c"
files = "*"
"#;
    let repo_cfg1 = RepoConfig::parse(initial_toml).unwrap();

    let engine1 = SyncEngine::new(
        "main",
        &sb.repo_dir,
        &repo_cfg1,
        &sb.state_db,
        vec![],
        OsInfo::detect(),
        None,
    )
    .with_home_dir(&sb.home_dir);
    let plans1 = engine1.plan(None, &lock).unwrap();
    engine1.import_files(&plans1, &lock, false).unwrap();

    // Now exclude orphan_a.conf, orphan_b.conf, and orphan_c.conf in dotler.toml
    let updated_toml = r#"[grp_a]
os-linux = "~/grp_a"
os-macos = "~/grp_a"
os-windows = "~/grp_a"
files = "keep_a.conf"

[grp_b]
os-linux = "~/grp_b"
os-macos = "~/grp_b"
os-windows = "~/grp_b"
files = "!*"

[grp_c]
os-linux = "~/grp_c"
os-macos = "~/grp_c"
os-windows = "~/grp_c"
files = "!*"
"#;
    let repo_cfg2 = RepoConfig::parse(updated_toml).unwrap();
    let engine2 = SyncEngine::new(
        "main",
        &sb.repo_dir,
        &repo_cfg2,
        &sb.state_db,
        vec![],
        OsInfo::detect(),
        None,
    )
    .with_home_dir(&sb.home_dir);

    // Tidy ONLY grp_a and grp_b with default KeepOnOs policy
    let report = engine2
        .tidy_groups(
            &["grp_a".to_string(), "grp_b".to_string()],
            &lock,
            TidyOrphanPolicy::default(),
            false,
        )
        .unwrap();

    assert_eq!(report.untracked_kept_orphans.len(), 2);
    assert!(dir_a.join("orphan_a.conf").is_file());
    assert!(dir_b.join("orphan_b.conf").is_file());
    assert!(
        sb.state_db
            .get_synced_file(&dir_a.join("orphan_a.conf").to_string_lossy())
            .unwrap()
            .is_none()
    );
    assert!(
        sb.state_db
            .get_synced_file(&dir_b.join("orphan_b.conf").to_string_lossy())
            .unwrap()
            .is_none()
    );

    // grp_a's active file and grp_c's untouched orphan must STILL remain tracked in synced_files
    assert!(
        sb.state_db
            .get_synced_file(&dir_a.join("keep_a.conf").to_string_lossy())
            .unwrap()
            .is_some()
    );
    assert!(
        sb.state_db
            .get_synced_file(&dir_c.join("orphan_c.conf").to_string_lossy())
            .unwrap()
            .is_some(),
        "Unselected group grp_c must not have its synced_files records touched"
    );
}

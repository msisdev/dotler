#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use dotler::config::repo::{OsInfo, RepoConfig, VaultConfig};
use dotler::config::state::{DotlerLock, DotlerLockGuard, StateDb};
use dotler::crypto::SecretString;
use dotler::crypto::keyring::{OsKeyring, PASSPHRASE_ENV_VAR};
use dotler::crypto::vault::{VaultKey, init_vault};
use dotler::engine::sync::SyncEngine;
use tempfile::TempDir;

pub static TEST_KEYRING_LOCK: Mutex<()> = Mutex::new(());

pub struct TestKeyringGuard<'a> {
    _lock: std::sync::MutexGuard<'a, ()>,
}

impl<'a> TestKeyringGuard<'a> {
    pub fn new() -> Self {
        let lock = TEST_KEYRING_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            std::env::remove_var(PASSPHRASE_ENV_VAR);
        }
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

pub struct SyncTestSandbox {
    pub root: TempDir,
    pub home_dir: PathBuf,
    pub dotler_dir: PathBuf,
    pub config_dir: PathBuf,
    pub repo_dir: PathBuf,
    pub backups_dir: PathBuf,
    pub state_db: StateDb,
    pub lock_path: PathBuf,
}

pub type ChallengeSandbox = SyncTestSandbox;
pub type TestSandbox = SyncTestSandbox;

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
        let config_dir = dotler_dir.clone();
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
            config_dir,
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
        fs::read(self.home_dir.join(rel_path)).ok()
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
        fs::read(self.repo_dir.join(rel_path)).ok()
    }

    pub fn write_dotler_toml(&self, toml_str: &str) {
        fs::write(self.repo_dir.join("dotler.toml"), toml_str).unwrap();
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

pub type MockGitRepo = MockBareRepo;
pub type TestGitRepo = MockBareRepo;

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

pub struct CliTestSandbox {
    pub _root: TempDir,
    pub home_dir: PathBuf,
    pub dotler_dir: PathBuf,
    pub repo_dir: PathBuf,
    pub bare_git_dir: PathBuf,
    pub mock_keyring: bool,
}

pub type E2eSandbox = CliTestSandbox;
pub type AgentTestSandbox = CliTestSandbox;

impl CliTestSandbox {
    pub fn new() -> Self {
        let toml = "[shell]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nos-bsd = \"~\"\nfiles = \"\"\"\n*\n\"\"\"\n";
        Self::with_seed(
            toml,
            Some(("shell/sample.sh", "#!/bin/sh\necho ok\n")),
            true,
        )
    }

    pub fn new_agent() -> Self {
        let toml = "[shell]\npath = \"~\"\nfiles = \"\"\"\n*\n!*.log\n\"\"\"\n";
        Self::with_seed(toml, None, false)
    }

    fn with_seed(seed_toml: &str, seed_file: Option<(&str, &str)>, mock_keyring: bool) -> Self {
        let root = tempfile::tempdir().expect("Failed to create temporary directory for sandbox");
        let root_path = root.path();
        let home_dir = root_path.join("home");
        let dotler_dir = home_dir.join(".config").join("dotler");
        let repo_dir = home_dir.join("dotfiles");
        let bare_git_dir = root_path.join("bare_repo.git");

        fs::create_dir_all(&dotler_dir).expect("Failed to create ~/.config/dotler");
        fs::create_dir_all(&repo_dir).expect("Failed to create dotfiles repository");

        let worktree = root_path.join("worktree");
        fs::create_dir_all(&worktree).unwrap();
        let wt = worktree.to_str().unwrap();
        Command::new("git").args(["init", wt]).status().unwrap();
        fs::write(worktree.join("dotler.toml"), seed_toml).unwrap();
        if let Some((rel, body)) = seed_file {
            let target = worktree.join(rel);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, body).unwrap();
        }
        Command::new("git")
            .args(["-C", wt, "config", "user.name", "Tester"])
            .status()
            .unwrap();
        Command::new("git")
            .args(["-C", wt, "config", "user.email", "test@example.com"])
            .status()
            .unwrap();
        Command::new("git")
            .args(["-C", wt, "add", "."])
            .status()
            .unwrap();
        Command::new("git")
            .args(["-C", wt, "commit", "-m", "Seed remote repo"])
            .status()
            .unwrap();
        Command::new("git")
            .args(["clone", "--bare", wt, bare_git_dir.to_str().unwrap()])
            .status()
            .unwrap();

        Self {
            _root: root,
            home_dir,
            dotler_dir,
            repo_dir,
            bare_git_dir,
            mock_keyring,
        }
    }

    pub fn cmd(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_dotler"));
        cmd.env("HOME", &self.home_dir)
            .env_remove("DOTLER_PASSPHRASE")
            .current_dir(&self.repo_dir)
            .stdin(Stdio::null());
        if self.mock_keyring {
            cmd.env("DOTLER_MOCK_KEYRING", "1");
        }
        cmd
    }

    pub fn _cmd_with_passphrase(&self, pass: &str) -> Command {
        let mut cmd = self.cmd();
        cmd.env("DOTLER_PASSPHRASE", pass);
        cmd
    }

    pub fn bin_cmd(&self) -> Command {
        self.cmd()
    }

    pub fn bin_cmd_with_passphrase(&self, pass: &str) -> Command {
        self._cmd_with_passphrase(pass)
    }

    pub fn spawn_mcp(&self) -> Child {
        self.mcp_cmd()
            .spawn()
            .expect("Failed to spawn dotler mcp process")
    }

    pub fn spawn_mcp_with_passphrase(&self, pass: &str) -> Child {
        let mut cmd = self.mcp_cmd();
        cmd.env("DOTLER_PASSPHRASE", pass);
        cmd.spawn()
            .expect("Failed to spawn dotler mcp process with passphrase")
    }

    fn mcp_cmd(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_dotler"));
        cmd.env("HOME", &self.home_dir)
            .env_remove("DOTLER_PASSPHRASE")
            .current_dir(&self.repo_dir)
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }
}

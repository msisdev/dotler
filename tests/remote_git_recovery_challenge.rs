mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{ChallengeSandbox, MockGitRepo};
use dotler::engine::EngineError;
use dotler::engine::remote::{clone_repo, install_remote, list_remote, parse_url, uninstall_remote};

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
os-nux = "~"
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
os-nux = "~"
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
os-nux = "~"
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
os-nux = "~"
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
os-nux = "~"
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
os-nux = "~"
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
os-nux = "~"
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
os-nux = "~"
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

mod common;

use std::fs;

use common::{MockBareRepo, SyncTestSandbox};
use dotler::config::state::SyncedFileRecord;
use dotler::engine::EngineError;
use dotler::engine::remote::{
    REMOTE_TOML_FETCH_MAX_BYTES, clone_repo, install_remote, list_remote, parse_url,
    uninstall_remote,
};

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
os-nux = "~"
files = "*.sh"

[nvim]
os-nux = "~/.config/nvim"
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
os-nux = "~"
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
os-nux = "~"
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
os-nux = "~/../../etc"
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
os-nux = "~"
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
os-nux = "~"
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
os-nux = "~"
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
os-nux = "~"
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
fn test_remote_git_multi_manifest_bfs_unicode_order_and_explicit_subpath() {
    let sb = SyncTestSandbox::new();
    let lock = sb.acquire_lock();

    // Seed a remote repository with NO root dotler.toml, and multiple nested dotler.toml files:
    // - z_cfg/dotler.toml (depth 1, lexicographically after a_cfg)
    // - a_cfg/dotler.toml (depth 1, lexicographically first at depth 1)
    // - a_cfg/deep/dotler.toml (depth 2)
    let worktree = sb.root.path().join("multi_worktree");
    let bare_repo = sb.root.path().join("multi_bare.git");
    fs::create_dir_all(worktree.join("z_cfg").join("zsh")).unwrap();
    fs::create_dir_all(worktree.join("a_cfg").join("nvim")).unwrap();
    fs::create_dir_all(worktree.join("a_cfg").join("deep").join("tmux")).unwrap();

    fs::write(
        worktree.join("z_cfg").join("dotler.toml"),
        "[zsh]\nos-nux = \"~\"\nos-mac = \"~\"\nfiles = \".zshrc\"\n",
    )
    .unwrap();
    fs::write(
        worktree.join("z_cfg").join("zsh").join(".zshrc"),
        "# from z_cfg\n",
    )
    .unwrap();

    fs::write(
        worktree.join("a_cfg").join("dotler.toml"),
        "[nvim]\nos-nux = \"~\"\nos-mac = \"~\"\nfiles = \"init.lua\"\n",
    )
    .unwrap();
    fs::write(
        worktree.join("a_cfg").join("nvim").join("init.lua"),
        "-- from a_cfg\n",
    )
    .unwrap();

    fs::write(
        worktree.join("a_cfg").join("deep").join("dotler.toml"),
        "[tmux]\nos-nux = \"~\"\nos-mac = \"~\"\nfiles = \".tmux.conf\"\n",
    )
    .unwrap();
    fs::write(
        worktree
            .join("a_cfg")
            .join("deep")
            .join("tmux")
            .join(".tmux.conf"),
        "# from deep\n",
    )
    .unwrap();

    let run_git = |dir: &std::path::Path, args: &[&str]| {
        let status = std::process::Command::new("git")
            .current_dir(dir)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
    };
    run_git(&worktree, &["init"]);
    run_git(&worktree, &["config", "user.email", "test@example.com"]);
    run_git(&worktree, &["config", "user.name", "Test"]);
    run_git(&worktree, &["add", "."]);
    run_git(&worktree, &["commit", "-m", "init multi"]);
    let status = std::process::Command::new("git")
        .args([
            "clone",
            "--bare",
            worktree.to_str().unwrap(),
            bare_repo.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let bare_url_str = bare_repo.to_string_lossy().to_string();

    // 1. `git ls` without subpath returns all 3 manifests in BFS + Unicode order:
    //    ["a_cfg/dotler.toml", "z_cfg/dotler.toml", "a_cfg/deep/dotler.toml"]
    let parsed_all = parse_url(&bare_url_str).unwrap();
    assert!(parsed_all.subpath.is_none());
    let summary = list_remote(&parsed_all, None, &lock).unwrap();
    let manifest_paths: Vec<&str> = summary.manifests.iter().map(|m| m.path.as_str()).collect();
    assert_eq!(
        manifest_paths,
        vec![
            "a_cfg/dotler.toml",
            "z_cfg/dotler.toml",
            "a_cfg/deep/dotler.toml"
        ]
    );
    // Primary groups default to first BFS + Unicode manifest (`a_cfg/dotler.toml` -> `nvim`)
    assert_eq!(summary.groups[0].name, "nvim");

    // 2. `git clone <git-url>` without subpath clones the first BFS + Unicode manifest (`a_cfg/dotler.toml`)
    let clone_default_dest = sb.root.path().join("cloned_default");
    let clone_rep1 = clone_repo(
        &parsed_all,
        &[],
        None,
        &clone_default_dest,
        None,
        None,
        None,
        &lock,
    )
    .unwrap();
    assert_eq!(clone_rep1.cloned_groups, vec!["nvim"]);
    assert!(clone_default_dest.join("dotler.toml").is_file());
    assert!(clone_default_dest.join("nvim").join("init.lua").is_file());

    // 3. `git clone <git-url>/<dotler.toml path>` clones the explicitly targeted manifest (`z_cfg/dotler.toml`)
    let explicit_url_str = format!("{bare_url_str}/z_cfg/dotler.toml");
    let parsed_explicit = parse_url(&explicit_url_str).unwrap();
    assert_eq!(parsed_explicit.subpath.as_deref(), Some("z_cfg"));
    let clone_explicit_dest = sb.root.path().join("cloned_explicit");
    let clone_rep2 = clone_repo(
        &parsed_explicit,
        &[],
        None,
        &clone_explicit_dest,
        None,
        None,
        None,
        &lock,
    )
    .unwrap();
    assert_eq!(clone_rep2.cloned_groups, vec!["zsh"]);
    assert!(clone_explicit_dest.join("dotler.toml").is_file());
    assert!(clone_explicit_dest.join("zsh").join(".zshrc").is_file());

    // 4. Shorthand URL with subpath (`gh:owner/repo/configs/linux/dotler.toml`)
    let gh_sub = parse_url("gh:owner/repo/configs/linux/dotler.toml").unwrap();
    assert_eq!(gh_sub.clone_url, "https://github.com/owner/repo.git");
    assert_eq!(gh_sub.subpath.as_deref(), Some("configs/linux"));
}


mod common;

use std::fs;

use common::SyncTestSandbox;
use dotler::config::repo::{OsInfo, RepoConfig};
use dotler::engine::sync::{SyncEngine, TidyOrphanPolicy};

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
os-nux = "~/grp_a"
os-mac = "~/grp_a"
os-win = "~/grp_a"
files = "*"

[grp_b]
os-nux = "~/grp_b"
os-mac = "~/grp_b"
os-win = "~/grp_b"
files = "*"

[grp_c]
os-nux = "~/grp_c"
os-mac = "~/grp_c"
os-win = "~/grp_c"
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
os-nux = "~/grp_a"
os-mac = "~/grp_a"
os-win = "~/grp_a"
files = "keep_a.conf"

[grp_b]
os-nux = "~/grp_b"
os-mac = "~/grp_b"
os-win = "~/grp_b"
files = "!*"

[grp_c]
os-nux = "~/grp_c"
os-mac = "~/grp_c"
os-win = "~/grp_c"
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

#[cfg(unix)]
#[test]
fn test_symlink_inside_repo_is_hard_blocked_exit_code_3() {
    use dotler::config::repo::is_symlink;
    use std::os::unix::fs::symlink;

    let sb = SyncTestSandbox::new();
    let lock = sb.acquire_lock();

    let shell_repo = sb.repo_dir.join("shell");
    fs::create_dir_all(&shell_repo).unwrap();
    let external_secret = sb.root.path().join("outside_secret.txt");
    fs::write(&external_secret, "TOP_SECRET").unwrap();

    // Create a symlink inside <repo>/shell/.zshrc -> outside_secret.txt
    let repo_link = shell_repo.join(".zshrc");
    symlink(&external_secret, &repo_link).unwrap();
    assert!(is_symlink(&repo_link));

    let toml = r#"[shell]
os-nux = "~"
os-mac = "~"
files = ".zshrc"
"#;
    fs::write(sb.repo_dir.join("dotler.toml"), toml).unwrap();
    let repo_cfg = RepoConfig::load(&sb.repo_dir.join("dotler.toml")).unwrap();

    let engine = sb.sync_engine(&repo_cfg, None);

    // 1. plan() must reject repo symlink with exit code 3
    let err = engine
        .plan(None, &lock)
        .expect_err("repo symlink must be blocked");
    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");

    // 2. tidy_groups() must also reject repo symlink with exit code 3
    let tidy_err = engine
        .tidy_groups(&[], &lock, TidyOrphanPolicy::KeepOnOs, false)
        .expect_err("tidy must reject repo symlink");
    assert_eq!(tidy_err.exit_code(), 3);

    // 3. dotler.toml itself being a symlink must be rejected by RepoConfig::load with exit code 3
    let symlink_toml = sb.root.path().join("symlink_dotler.toml");
    symlink(sb.repo_dir.join("dotler.toml"), &symlink_toml).unwrap();
    let load_err = RepoConfig::load(&symlink_toml).expect_err("symlink dotler.toml must fail");
    assert_eq!(load_err.exit_code(), 3);
}

#[cfg(unix)]
#[test]
fn test_os_parent_dir_and_file_symlink_escaping_home_are_hard_blocked() {
    use std::os::unix::fs::symlink;

    let sb = SyncTestSandbox::new();
    let lock = sb.acquire_lock();

    // Outside directory (sibling of home_dir inside root)
    let outside_dir = sb.root.path().join("outside_system_dir");
    fs::create_dir_all(&outside_dir).unwrap();
    let outside_file = outside_dir.join("passwd_mock");
    fs::write(&outside_file, "root:x:0:0").unwrap();

    // Case 1: OS file symlink ~/.zshrc -> outside_file
    symlink(&outside_file, sb.home_dir.join(".zshrc")).unwrap();

    let toml1 = r#"[shell]
os-nux = "~"
os-mac = "~"
files = ".zshrc"
"#;
    let repo_cfg1 = RepoConfig::parse(toml1).unwrap();
    let engine1 = sb.sync_engine(&repo_cfg1, None);
    let err1 = engine1
        .plan(None, &lock)
        .expect_err("OS symlink escaping home must be blocked");
    assert_eq!(err1.exit_code(), 3);
    assert_eq!(err1.error_code(), "SECURITY_BLOCKED");

    let _ = fs::remove_file(sb.home_dir.join(".zshrc"));

    // Case 2: OS parent directory symlink ~/.config/evil_app -> outside_dir
    let config_dir = sb.home_dir.join(".config");
    fs::create_dir_all(&config_dir).unwrap();
    symlink(&outside_dir, config_dir.join("evil_app")).unwrap();

    let toml2 = r#"[evil]
os-nux = "~/.config/evil_app"
os-mac = "~/.config/evil_app"
files = "passwd_mock"
"#;
    let repo_cfg2 = RepoConfig::parse(toml2).unwrap();
    let engine2 = sb.sync_engine(&repo_cfg2, None);
    let err2 = engine2
        .plan(None, &lock)
        .expect_err("OS parent dir symlink escaping home must be blocked");
    assert_eq!(err2.exit_code(), 3);
    assert_eq!(err2.error_code(), "SECURITY_BLOCKED");
}

#[cfg(unix)]
#[test]
fn test_os_broken_in_home_symlink_blocks_import_and_heals_on_export() {
    use dotler::config::repo::is_symlink;
    use std::os::unix::fs::symlink;

    let sb = SyncTestSandbox::new();
    let lock = sb.acquire_lock();

    // Create a broken in-home symlink: ~/.zshrc -> ~/nonexistent_stow/.zshrc
    let home_zshrc = sb.home_dir.join(".zshrc");
    symlink(
        sb.home_dir.join("nonexistent_stow").join(".zshrc"),
        &home_zshrc,
    )
    .unwrap();
    assert!(is_symlink(&home_zshrc));
    assert!(!home_zshrc.exists());

    let toml = r#"[shell]
os-nux = "~"
os-mac = "~"
files = ".zshrc"
"#;
    let repo_cfg = RepoConfig::parse(toml).unwrap();
    let engine = sb.sync_engine(&repo_cfg, None);

    // 1. import_files must reject broken OS symlink with exit code 3
    let plans = engine.plan(None, &lock).unwrap();
    let import_err = engine
        .import_files(&plans, &lock, false)
        .expect_err("broken OS symlink must fail on import");
    assert_eq!(import_err.exit_code(), 3);

    // 2. When repo has a valid .zshrc, export_files replaces the broken symlink with a real file
    let repo_shell = sb.repo_dir.join("shell");
    fs::create_dir_all(&repo_shell).unwrap();
    fs::write(repo_shell.join(".zshrc"), "export ZSH_HEALED=1\n").unwrap();

    let plans_for_export = engine.plan(None, &lock).unwrap();
    let export_rep = engine
        .export_files(&plans_for_export, &lock, false, false)
        .unwrap();
    assert_eq!(export_rep.processed, 1);
    assert!(
        !is_symlink(&home_zshrc),
        "broken symlink must be replaced by a regular file"
    );
    assert!(home_zshrc.is_file());
    assert_eq!(
        fs::read_to_string(&home_zshrc).unwrap(),
        "export ZSH_HEALED=1\n"
    );
}

#[cfg(unix)]
#[test]
fn test_os_in_home_symlink_migration_import_dereferences_and_export_materializes() {
    use dotler::config::repo::is_symlink;
    use std::os::unix::fs::symlink;

    let sb = SyncTestSandbox::new();
    let lock = sb.acquire_lock();

    // Simulate GNU Stow setup inside ~: ~/stow-dots/zsh/.zshrc and ~/.zshrc -> ~/stow-dots/zsh/.zshrc
    let stow_dir = sb.home_dir.join("stow-dots").join("zsh");
    fs::create_dir_all(&stow_dir).unwrap();
    let stow_zshrc = stow_dir.join(".zshrc");
    fs::write(&stow_zshrc, "# migrated from stow\n").unwrap();

    let home_zshrc = sb.home_dir.join(".zshrc");
    symlink(&stow_zshrc, &home_zshrc).unwrap();
    assert!(is_symlink(&home_zshrc));

    let toml = r#"[shell]
os-nux = "~"
os-mac = "~"
files = ".*rc"
"#;
    let repo_cfg = RepoConfig::parse(toml).unwrap();
    let engine = sb.sync_engine(&repo_cfg, None);

    // Step 1: Import dereferences the in-home symlink and stores a pure regular file in <repo>/shell/.zshrc
    let plans1 = engine.plan(None, &lock).unwrap();
    assert_eq!(plans1.len(), 1);
    let import_rep = engine.import_files(&plans1, &lock, false).unwrap();
    assert_eq!(import_rep.processed, 1);

    let repo_zshrc = sb.repo_dir.join("shell").join(".zshrc");
    assert!(repo_zshrc.is_file());
    assert!(
        !is_symlink(&repo_zshrc),
        "imported repo file must be a pure regular file, never a symlink"
    );
    assert_eq!(
        fs::read_to_string(&repo_zshrc).unwrap(),
        "# migrated from stow\n"
    );

    // Step 2: Export runs when os_hash == repo_hash, but because ~/.zshrc is still a symlink,
    // export MUST NOT skip; it must materialize ~/.zshrc into an independent regular file!
    let plans2 = engine.plan(None, &lock).unwrap();
    let export_rep = engine.export_files(&plans2, &lock, false, false).unwrap();
    assert_eq!(
        export_rep.processed, 1,
        "export must process (not skip) an OS symlink even when hashes match"
    );
    assert_eq!(export_rep.skipped, 0);
    assert!(
        !is_symlink(&home_zshrc),
        "~/.zshrc must be materialized into a standalone regular file after export"
    );
    assert!(home_zshrc.is_file());
    assert_eq!(
        fs::read_to_string(&home_zshrc).unwrap(),
        "# migrated from stow\n"
    );

    // Step 3: Subsequent export now skips because ~/.zshrc is already a regular file with matching hash
    let plans3 = engine.plan(None, &lock).unwrap();
    let export_rep2 = engine.export_files(&plans3, &lock, false, false).unwrap();
    assert_eq!(export_rep2.processed, 0);
    assert_eq!(export_rep2.skipped, 1);
}


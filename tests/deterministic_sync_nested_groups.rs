//! Integration tests for hierarchical dot-notation sub-groups (`[parent.child]`),
//! root-only path derivation, most-specific subtree delegation, subtree CLI filtering,
//! `tidy` in-repo relocation across parent and sub-groups, and remote Git selective operations.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use dotler::config::local::LocalConfig;
use dotler::config::repo::{OsInfo, RepoConfig, format_vault_root_keys};
use dotler::config::state::{DotlerLock, StateDb};
use dotler::core::context::CoreContext;
use dotler::crypto::SecretString;
use dotler::crypto::keyring::PASSPHRASE_ENV_VAR;
use dotler::crypto::vault::{FULL_ENC_SUFFIX, init_vault};
use dotler::engine::{
    FileSyncStatus, GroupSelector, NoopObserver, SyncEngine, TidyOrphanPolicy, clone_repo,
    install_remote_with_options, list_remote, parse_url, run_check, run_export, run_import,
    run_status, uninstall_remote,
};

static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn count_fenc_files_nonrecursive(dir: &Path) -> usize {
    if !dir.is_dir() {
        return 0;
    }
    fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_type().is_ok_and(|t| t.is_file())
                && e.file_name().to_string_lossy().ends_with(FULL_ENC_SUFFIX)
        })
        .count()
}

fn make_context(home_dir: &Path, _repo_dir: &Path, cwd: &Path) -> CoreContext {
    let dotler_cfg_dir = home_dir.join(".config").join("dotler");
    fs::create_dir_all(&dotler_cfg_dir).unwrap();
    let local_cfg = LocalConfig {
        default_devices: vec!["dev".to_string()],
        use_keyring: false,
        ..Default::default()
    };
    local_cfg
        .save_atomic(&dotler_cfg_dir.join("config.toml"))
        .unwrap();

    CoreContext::with_paths(
        dotler_cfg_dir.join("dotler.lock"),
        dotler_cfg_dir.join("config.toml"),
        dotler_cfg_dir.join("state.db"),
        None,
        Some("dev".to_string()),
        false,
    )
    .with_cwd(cwd)
}

#[test]
fn test_nested_vault_subgroups_full_encryption_delegation_and_subtree_filters() {
    let _env_guard = ENV_MUTEX.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let home_dir = tmp.path().join("home");
    let workspace = home_dir.join("vault-project");
    let notes_dir = workspace.join("notes");
    fs::create_dir_all(notes_dir.join("problems").join("2026")).unwrap();
    fs::create_dir_all(notes_dir.join("sleep")).unwrap();
    fs::create_dir_all(notes_dir.join("misc")).unwrap();

    fs::write(notes_dir.join("index.md"), b"# Root Index\n").unwrap();
    fs::write(
        notes_dir.join("misc/unlisted.md"),
        b"unlisted domain fallback\n",
    )
    .unwrap();
    fs::write(
        notes_dir.join("problems/2026/sensitive-issue.md"),
        b"deep problem content\n",
    )
    .unwrap();
    fs::write(notes_dir.join("sleep/2026-11-20.md"), b"sleep log\n").unwrap();

    let pass_raw = "nested-vault-pass-123";
    let pass = SecretString::new(pass_raw.to_string());
    let (vcfg, vkey, _) = init_vault(&pass).unwrap();
    unsafe {
        std::env::set_var(PASSPHRASE_ENV_VAR, pass_raw);
    }

    let manifest = format!(
        "{}\n[vault]\nos-nux = \"./notes\"\nos-mac = \"./notes\"\nos-win = \"./notes\"\nos-bsd = \"./notes\"\nfiles = \"* enc=full\"\n\n[vault.problems]\nfiles = \"* enc=full\"\n\n[vault.sleep]\nfiles = \"* enc=full\"\n",
        format_vault_root_keys(&vcfg)
    );
    fs::write(workspace.join("dotler.toml"), &manifest).unwrap();

    let ctx = make_context(&home_dir, &workspace, &workspace);
    let lock = DotlerLock::new(home_dir.join(".config/dotler/dotler.lock"))
        .acquire(Duration::from_millis(500), Duration::from_millis(10))
        .unwrap();

    let check_all = run_check(&ctx, None, &lock).unwrap();
    assert_eq!(check_all.groups_checked, 3);
    let check_sub = run_check(&ctx, Some("vault.sleep"), &lock).unwrap();
    assert_eq!(check_sub.groups_checked, 1);

    // Import only `vault.sleep` first via narrow filter
    let mut obs = NoopObserver;
    let sleep_import = run_import(
        &ctx,
        &["vault.sleep".to_string()],
        false,
        false,
        &lock,
        &mut obs,
    )
    .unwrap();
    assert_eq!(sleep_import.processed, 1);
    assert_eq!(
        count_fenc_files_nonrecursive(&workspace.join("vault/sleep")),
        1
    );
    assert_eq!(count_fenc_files_nonrecursive(&workspace.join("vault")), 0);

    // Import entire `vault` subtree (`vault`, `vault.problems`, `vault.sleep`)
    let full_import =
        run_import(&ctx, &["vault".to_string()], false, false, &lock, &mut obs).unwrap();
    assert_eq!(full_import.processed, 3);
    assert_eq!(full_import.skipped, 1);

    // Verify exact directory partitioning in `vault/`
    assert_eq!(
        count_fenc_files_nonrecursive(&workspace.join("vault")),
        2,
        "only root index.md and unlisted misc/unlisted.md should live at vault/ root"
    );
    assert_eq!(
        count_fenc_files_nonrecursive(&workspace.join("vault/problems")),
        1
    );
    assert_eq!(
        count_fenc_files_nonrecursive(&workspace.join("vault/sleep")),
        1
    );

    // Wipe plaintext `./notes` and restore cleanly via `dotler export vault`
    fs::remove_dir_all(&notes_dir).unwrap();
    let export_report =
        run_export(&ctx, &["vault".to_string()], false, false, &lock, &mut obs).unwrap();
    assert_eq!(export_report.processed, 4);
    assert_eq!(
        fs::read(notes_dir.join("index.md")).unwrap(),
        b"# Root Index\n"
    );
    assert_eq!(
        fs::read(notes_dir.join("misc/unlisted.md")).unwrap(),
        b"unlisted domain fallback\n"
    );
    assert_eq!(
        fs::read(notes_dir.join("problems/2026/sensitive-issue.md")).unwrap(),
        b"deep problem content\n"
    );
    assert_eq!(
        fs::read(notes_dir.join("sleep/2026-11-20.md")).unwrap(),
        b"sleep log\n"
    );

    let statuses = run_status(&ctx, Some("vault"), &lock).unwrap();
    assert_eq!(statuses.len(), 4);
    assert!(statuses.iter().all(|p| p.status == FileSyncStatus::Synced));

    unsafe {
        std::env::remove_var(PASSPHRASE_ENV_VAR);
    }
    drop(vkey);
}

#[test]
fn test_tidy_relocates_full_encrypted_archives_between_parent_and_subgroup_losslessly() {
    let _env_guard = ENV_MUTEX.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let home_dir = tmp.path().join("home");
    let workspace = home_dir.join("project");
    let notes_dir = workspace.join("notes");
    fs::create_dir_all(notes_dir.join("career")).unwrap();
    fs::create_dir_all(home_dir.join(".config/dotler")).unwrap();
    fs::write(notes_dir.join("root.md"), b"root body").unwrap();
    fs::write(notes_dir.join("career/roadmap.md"), b"career roadmap").unwrap();

    let pass = SecretString::new("relocate-pass-456".to_string());
    let (vcfg, vkey, _) = init_vault(&pass).unwrap();

    // Step 1: Start with a single `[vault]` group
    let toml_single = format!(
        "{}\n[vault]\nos-nux = \"./notes\"\nos-mac = \"./notes\"\nos-win = \"./notes\"\nos-bsd = \"./notes\"\nfiles = \"* enc=full\"\n",
        format_vault_root_keys(&vcfg)
    );
    fs::write(workspace.join("dotler.toml"), &toml_single).unwrap();

    let state_db = StateDb::open(&home_dir.join(".config/dotler/state.db")).unwrap();
    let lock = DotlerLock::new(home_dir.join(".config/dotler/dotler.lock"))
        .acquire(Duration::from_millis(500), Duration::from_millis(10))
        .unwrap();
    let os_info = OsInfo::new("arch", "nux");

    let cfg1 = RepoConfig::parse(&toml_single).unwrap();
    let engine1 = SyncEngine::new(
        "default",
        &workspace,
        &cfg1,
        &state_db,
        vec![],
        os_info.clone(),
        Some(&vkey),
    )
    .with_home_dir(&home_dir)
    .with_cwd(&workspace);

    let plans1 = engine1.plan(None, &lock).unwrap();
    engine1.import_files(&plans1, &lock, false).unwrap();
    assert_eq!(count_fenc_files_nonrecursive(&workspace.join("vault")), 2);

    // Step 2: Add `[vault.career]` to split `career/` into `vault/career/`
    let toml_split = format!("{toml_single}\n[vault.career]\nfiles = \"* enc=full\"\n");
    fs::write(workspace.join("dotler.toml"), &toml_split).unwrap();
    let cfg2 = RepoConfig::parse(&toml_split).unwrap();
    let engine2 = SyncEngine::new(
        "default",
        &workspace,
        &cfg2,
        &state_db,
        vec![],
        os_info.clone(),
        Some(&vkey),
    )
    .with_home_dir(&home_dir)
    .with_cwd(&workspace);

    let pre_tidy_plans = engine2.plan(None, &lock).unwrap();
    let career_plan = pre_tidy_plans
        .iter()
        .find(|p| p.group_name == "vault.career")
        .expect("vault.career plan must exist");
    assert_eq!(career_plan.status, FileSyncStatus::EncryptionMismatch);

    let tidy_split = engine2
        .tidy(None, &lock, TidyOrphanPolicy::KeepOnOs, false)
        .unwrap();
    assert_eq!(tidy_split.encrypted_in_repo, 1);
    assert!(tidy_split.untracked_kept_orphans.is_empty());
    assert_eq!(count_fenc_files_nonrecursive(&workspace.join("vault")), 1);
    assert_eq!(
        count_fenc_files_nonrecursive(&workspace.join("vault/career")),
        1
    );

    let rec_after_split = state_db
        .get_synced_file(&notes_dir.join("career/roadmap.md").to_string_lossy())
        .unwrap()
        .unwrap();
    assert_eq!(rec_after_split.group_name, "vault.career");
    assert_eq!(rec_after_split.relative_path, "roadmap.md");

    let post_split_plans = engine2.plan(None, &lock).unwrap();
    assert!(
        post_split_plans
            .iter()
            .all(|p| p.status == FileSyncStatus::Synced)
    );

    // Step 3: Remove `[vault.career]` to merge `vault/career/` back into `[vault]`
    fs::write(workspace.join("dotler.toml"), &toml_single).unwrap();
    let engine3 = SyncEngine::new(
        "default",
        &workspace,
        &cfg1,
        &state_db,
        vec![],
        os_info,
        Some(&vkey),
    )
    .with_home_dir(&home_dir)
    .with_cwd(&workspace);

    let pre_merge_plans = engine3.plan(None, &lock).unwrap();
    let merged_plan = pre_merge_plans
        .iter()
        .find(|p| p.relative_path == "career/roadmap.md")
        .expect("merged plan must exist");
    assert_eq!(merged_plan.status, FileSyncStatus::EncryptionMismatch);

    let tidy_merge = engine3
        .tidy(None, &lock, TidyOrphanPolicy::KeepOnOs, false)
        .unwrap();
    assert_eq!(tidy_merge.encrypted_in_repo, 1);
    assert!(
        !workspace.join("vault/career").exists(),
        "empty vault/career directory must be pruned"
    );
    assert_eq!(count_fenc_files_nonrecursive(&workspace.join("vault")), 2);

    let rec_after_merge = state_db
        .get_synced_file(&notes_dir.join("career/roadmap.md").to_string_lossy())
        .unwrap()
        .unwrap();
    assert_eq!(rec_after_merge.group_name, "vault");
    assert_eq!(rec_after_merge.relative_path, "career/roadmap.md");

    let post_merge_plans = engine3.plan(None, &lock).unwrap();
    assert!(
        post_merge_plans
            .iter()
            .all(|p| p.status == FileSyncStatus::Synced)
    );
}

#[test]
fn test_remote_git_ls_clone_and_install_with_nested_subgroups() {
    let _env_guard = ENV_MUTEX.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let wt = tmp.path().join("remote-wt");
    let bare = tmp.path().join("remote.git");
    fs::create_dir_all(wt.join("config/nvim")).unwrap();
    fs::create_dir_all(wt.join("config/waybar")).unwrap();

    let remote_toml = r#"
[config]
os-nux = "~/.config"
os-mac = "~/.config"
os-win = "~/.config"
os-bsd = "~/.config"

[config.nvim]
files = "init.lua"

[config.waybar]
files = "style.css"
"#;
    fs::write(wt.join("dotler.toml"), remote_toml).unwrap();
    fs::write(wt.join("config/nvim/init.lua"), b"-- remote nvim\n").unwrap();
    fs::write(wt.join("config/waybar/style.css"), b"/* waybar */\n").unwrap();

    let run_git = |args: &[&str], dir: &Path| {
        let st = Command::new("git")
            .args(args)
            .current_dir(dir)
            .status()
            .unwrap();
        assert!(st.success());
    };
    run_git(&["init", "-b", "main"], &wt);
    run_git(&["config", "user.name", "Tester"], &wt);
    run_git(&["config", "user.email", "test@example.com"], &wt);
    run_git(&["add", "."], &wt);
    run_git(&["commit", "-m", "seed nested groups"], &wt);
    run_git(
        &[
            "clone",
            "--bare",
            wt.to_str().unwrap(),
            bare.to_str().unwrap(),
        ],
        tmp.path(),
    );

    let url = parse_url(&format!("file://{}", bare.display())).unwrap();
    let home_dir = tmp.path().join("local-home");
    let dotler_dir = home_dir.join(".config/dotler");
    fs::create_dir_all(&dotler_dir).unwrap();
    let lock = DotlerLock::new(dotler_dir.join("dotler.lock"))
        .acquire(Duration::from_millis(500), Duration::from_millis(10))
        .unwrap();

    // 1. `git ls` omits pure anchor `[config]` and reports derived paths on sub-groups
    let summary = list_remote(&url, None, &lock).unwrap();
    let names: Vec<&str> = summary.groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, vec!["config.nvim", "config.waybar"]);
    assert_eq!(
        summary.groups[0]
            .target_paths
            .get("os-nux")
            .map(String::as_str),
        Some("~/.config/nvim")
    );

    // 2. `git clone <url> config.nvim` preserves root `[config]` anchor + `[config.nvim]`
    let clone_sub_dir = home_dir.join("cloned-sub");
    clone_repo(
        &url,
        &[GroupSelector::parse("config.nvim")],
        None,
        &clone_sub_dir,
        None,
        None,
        None,
        &lock,
    )
    .unwrap();
    let cloned_sub_cfg = RepoConfig::load(&clone_sub_dir.join("dotler.toml")).unwrap();
    assert!(cloned_sub_cfg.is_anchor_only_group("config"));
    assert!(cloned_sub_cfg.groups.contains_key("config.nvim"));
    assert!(!cloned_sub_cfg.groups.contains_key("config.waybar"));
    assert!(clone_sub_dir.join("config/nvim/init.lua").is_file());
    assert!(!clone_sub_dir.join("config/waybar").exists());

    // 3. `git clone <url> config.nvim:my_nvim` promotes derived path to standalone top-level `[my_nvim]`
    let clone_alias_dir = home_dir.join("cloned-alias");
    clone_repo(
        &url,
        &[GroupSelector::parse("config.nvim:my_nvim")],
        None,
        &clone_alias_dir,
        None,
        None,
        None,
        &lock,
    )
    .unwrap();
    let cloned_alias_cfg = RepoConfig::load(&clone_alias_dir.join("dotler.toml")).unwrap();
    assert!(cloned_alias_cfg.groups.contains_key("my_nvim"));
    assert!(!cloned_alias_cfg.groups.contains_key("config"));
    assert_eq!(
        cloned_alias_cfg.groups["my_nvim"]
            .paths
            .get("os-nux")
            .map(String::as_str),
        Some("~/.config/nvim")
    );
    assert!(clone_alias_dir.join("my_nvim/init.lua").is_file());

    // 4. `git install <url> config` installs entire `config.*` subtree and `git uninstall config` restores
    let state_db = StateDb::open(&dotler_dir.join("state.db")).unwrap();
    let mut obs = NoopObserver;
    let existing_nvim: PathBuf = home_dir.join(".config/nvim/init.lua");
    fs::create_dir_all(existing_nvim.parent().unwrap()).unwrap();
    fs::write(&existing_nvim, b"-- local original\n").unwrap();

    let inst = install_remote_with_options(
        &url,
        &["config".to_string()],
        None,
        None,
        &[],
        &state_db,
        &lock,
        false,
        false,
        false,
        None,
        &mut obs,
    )
    .unwrap();
    assert_eq!(inst.installed_files.len(), 2);
    assert_eq!(fs::read(&existing_nvim).unwrap(), b"-- remote nvim\n");
    assert_eq!(
        fs::read(home_dir.join(".config/waybar/style.css")).unwrap(),
        b"/* waybar */\n"
    );

    let uninst = uninstall_remote(&["config".to_string()], &state_db, &lock, false).unwrap();
    assert_eq!(uninst.restored_backups.len(), 1);
    assert_eq!(uninst.removed_files.len(), 1);
    assert_eq!(fs::read(&existing_nvim).unwrap(), b"-- local original\n");
    assert!(!home_dir.join(".config/waybar/style.css").exists());
}

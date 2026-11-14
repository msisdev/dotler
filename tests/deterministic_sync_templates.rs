mod common;

use std::fs;

use common::{MockBareRepo, SyncTestSandbox};
use dotler::config::repo::RepoConfig;
use dotler::crypto::ExposeSecret;
use dotler::crypto::vault::EncryptedFile;
use dotler::engine::remote::{install_remote, parse_url};
use dotler::engine::sync::{FileSyncStatus, TidyOrphanPolicy};

#[test]
fn test_directory_selection_rules_without_wildcard_import_export_and_tidy() {
    let sb = SyncTestSandbox::new();
    let lock = sb.acquire_lock();

    let nvim_dir = sb.home_dir.join(".config").join("nvim");
    fs::create_dir_all(nvim_dir.join("lua").join("plugins")).unwrap();
    fs::create_dir_all(nvim_dir.join("cache").join("nested")).unwrap();
    fs::create_dir_all(nvim_dir.join("logs")).unwrap();

    fs::write(nvim_dir.join("init.lua"), "require('core')\n").unwrap();
    fs::write(nvim_dir.join("lua").join("core.lua"), "return {}\n").unwrap();
    fs::write(
        nvim_dir.join("lua").join("plugins").join("telescope.lua"),
        "return { 'telescope' }\n",
    )
    .unwrap();
    fs::write(nvim_dir.join("cache").join("state.bin"), "cached\n").unwrap();
    fs::write(
        nvim_dir.join("cache").join("nested").join("index.bin"),
        "nested cached\n",
    )
    .unwrap();
    fs::write(nvim_dir.join("logs").join("debug.log"), "log\n").unwrap();

    // Import using `lua` (directory rule without `/*`), `!cache`, and `!logs/`
    let toml = r#"[nvim]
os-nux = "~/.config/nvim"
os-mac = "~/.config/nvim"
files = """
init.lua
lua
!cache
!logs/
"""
"#;
    let repo_cfg = RepoConfig::parse(toml).unwrap();
    let engine = sb.sync_engine(&repo_cfg, None);

    let plans = engine.plan(None, &lock).unwrap();
    let planned_rels: Vec<&str> = plans.iter().map(|p| p.relative_path.as_str()).collect();
    assert_eq!(
        planned_rels,
        vec!["init.lua", "lua/core.lua", "lua/plugins/telescope.lua",]
    );

    let import_rep = engine.import_files(&plans, &lock, false).unwrap();
    assert_eq!(import_rep.processed, 3);
    assert!(sb.repo_dir.join("nvim/init.lua").is_file());
    assert!(sb.repo_dir.join("nvim/lua/core.lua").is_file());
    assert!(sb.repo_dir.join("nvim/lua/plugins/telescope.lua").is_file());
    assert!(!sb.repo_dir.join("nvim/cache").exists());
    assert!(!sb.repo_dir.join("nvim/logs").exists());

    // Now exclude `lua/plugins` (without `/*`) and verify `Orphaned` status + `tidy` cleanup
    let toml_after = r#"[nvim]
os-nux = "~/.config/nvim"
os-mac = "~/.config/nvim"
files = """
init.lua
lua
!lua/plugins
!cache
!logs/
"""
"#;
    let repo_cfg_after = RepoConfig::parse(toml_after).unwrap();
    let engine_after = sb.sync_engine(&repo_cfg_after, None);
    let plans_after = engine_after.plan(None, &lock).unwrap();
    let orphan_plan = plans_after
        .iter()
        .find(|p| p.relative_path == "lua/plugins/telescope.lua")
        .expect("excluded directory child must be detected as Orphaned");
    assert_eq!(orphan_plan.status, FileSyncStatus::Orphaned);

    let tidy_rep = engine_after
        .tidy(None, &lock, TidyOrphanPolicy::KeepOnOs, false)
        .unwrap();
    assert_eq!(tidy_rep.removed_from_repo, 1);
    assert!(!sb.repo_dir.join("nvim/lua/plugins/telescope.lua").exists());
    assert!(
        nvim_dir.join("lua/plugins/telescope.lua").is_file(),
        "OS file must never be deleted by tidy with KeepOnOs"
    );

    // Also verify `install_remote` honors standalone directory include (`lua`) and exclude (`!lua/plugins`)
    // and skips unselected sibling files (`cache/state.bin`)
    let remote_mock = MockBareRepo::new(
        toml_after,
        &[
            ("nvim/init.lua", b"-- remote init\n"),
            ("nvim/lua/core.lua", b"-- remote core\n"),
            ("nvim/lua/plugins/telescope.lua", b"-- excluded plugin\n"),
            ("nvim/unselected/extra.txt", b"-- unselected\n"),
        ],
    );
    let remote_url = parse_url(&remote_mock.clone_url).unwrap();
    let deploy_dir = sb.home_dir.join("remote_deploy");
    let install_rep = install_remote(
        &remote_url,
        &["nvim".to_string()],
        Some(&deploy_dir),
        None,
        &[],
        &sb.state_db,
        &lock,
    )
    .unwrap();
    assert_eq!(install_rep.installed_files.len(), 2);
    assert!(deploy_dir.join("init.lua").is_file());
    assert!(deploy_dir.join("lua/core.lua").is_file());
    assert!(!deploy_dir.join("lua/plugins/telescope.lua").exists());
    assert!(!deploy_dir.join("unselected/extra.txt").exists());
}

#[test]
fn test_home_template_bidirectional_import_export_tidy_and_remote_install() {
    let sb = SyncTestSandbox::new();
    let lock = sb.acquire_lock();
    let (vault_cfg, vault_key) = sb.create_vault("tmpl-vault-passphrase");

    let home_str = sb.home_dir.to_string_lossy().replace('\\', "/");
    let home_str = home_str.trim_end_matches('/');

    let toml = format!(
        r#"
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[shell]
os-nux = "~"
os-mac = "~"
files = """
.gitconfig tmpl
.credentials enc tmpl
"""
"#,
        vault_cfg.vault_id, vault_cfg.password_slot, vault_cfg.recovery_slot
    );
    sb.write_dotler_toml(&toml);
    let repo_cfg = RepoConfig::parse(&toml).unwrap();

    // 1. Write OS files containing the machine's concrete home directory path
    let os_gitconfig = format!("[core]\nexcludesfile = {home_str}/.gitignore_global\n");
    let os_creds = format!("token_file = {home_str}/.tokens/prod.key\n");
    sb.write_home_file(".gitconfig", os_gitconfig.as_bytes());
    sb.write_home_file(".credentials", os_creds.as_bytes());

    let engine = sb.sync_engine(&repo_cfg, Some(&vault_key));
    let plans1 = engine.plan(None, &lock).unwrap();
    assert_eq!(plans1.len(), 2);
    assert!(plans1.iter().all(|p| p.is_template));

    // 2. Import: OS home path is reverse-substituted into `{{ $HOME }}` inside the repository
    let imp1 = engine.import_files(&plans1, &lock, false).unwrap();
    assert_eq!(imp1.processed, 2);

    let repo_gitconfig = sb.read_repo_file("shell/.gitconfig").unwrap();
    assert_eq!(
        std::str::from_utf8(&repo_gitconfig).unwrap(),
        "[core]\nexcludesfile = {{ $HOME }}/.gitignore_global\n"
    );

    let repo_creds_enc = sb.read_repo_file("shell/.credentials.enc").unwrap();
    let enc_file = EncryptedFile::from_bytes(&repo_creds_enc).unwrap();
    let dec_creds = vault_key.decrypt_file(&enc_file).unwrap();
    assert_eq!(
        std::str::from_utf8(dec_creds.expose_secret()).unwrap(),
        "token_file = {{ $HOME }}/.tokens/prod.key\n"
    );

    // 3. Re-plan & re-import: must be `Synced` and skip re-writing / re-encrypting
    let plans2 = engine.plan(None, &lock).unwrap();
    assert!(plans2.iter().all(|p| p.status == FileSyncStatus::Synced));
    let imp2 = engine.import_files(&plans2, &lock, false).unwrap();
    assert_eq!(imp2.skipped, 2);
    assert_eq!(imp2.processed, 0);
    assert_eq!(
        sb.read_repo_file("shell/.credentials.enc").unwrap(),
        repo_creds_enc
    );

    // 4. Delete OS files and export from repository: `{{ $HOME }}` renders back to `home_str`
    fs::remove_file(sb.home_dir.join(".gitconfig")).unwrap();
    fs::remove_file(sb.home_dir.join(".credentials")).unwrap();

    let plans3 = engine.plan(None, &lock).unwrap();
    assert!(
        plans3
            .iter()
            .all(|p| p.status == FileSyncStatus::MissingLocally)
    );
    let exp1 = engine.export_files(&plans3, &lock, false, false).unwrap();
    assert_eq!(exp1.processed, 2);

    assert_eq!(
        sb.read_home_file(".gitconfig").unwrap(),
        os_gitconfig.as_bytes()
    );
    assert_eq!(
        sb.read_home_file(".credentials").unwrap(),
        os_creds.as_bytes()
    );

    // 5. Tidy: switching `.credentials enc tmpl` -> `.credentials tmpl` decrypts in-place while preserving `{{ $HOME }}`
    let toml_plain_tmpl = r#"
[shell]
os-nux = "~"
os-mac = "~"
files = """
.gitconfig tmpl
.credentials tmpl
"""
"#;
    sb.write_dotler_toml(toml_plain_tmpl);
    let repo_cfg_plain = RepoConfig::parse(toml_plain_tmpl).unwrap();
    let engine_plain = sb.sync_engine(&repo_cfg_plain, Some(&vault_key));
    let tidy_rep = engine_plain
        .tidy(None, &lock, TidyOrphanPolicy::KeepOnOs, false)
        .unwrap();
    assert_eq!(tidy_rep.decrypted_in_repo, 1);
    assert_eq!(
        std::str::from_utf8(&sb.read_repo_file("shell/.credentials").unwrap()).unwrap(),
        "token_file = {{ $HOME }}/.tokens/prod.key\n"
    );

    // 6. Binary file with `tmpl` attribute must be rejected
    sb.write_home_file(".gitconfig", b"\x00\x01\x02binary");
    assert!(engine_plain.plan(None, &lock).is_err());
}

//! Remote Git staging clone, group selection/aliasing, and vault re-keying (`git clone`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::local::{
    LocalConfig, WalkDir, format_home_repo_path, resolve_home_for_config_path,
};
use crate::config::repo::{
    RepoConfig, VaultConfig, update_vault_manifest_section, validate_path_security,
};
use crate::config::state::{DotlerLockGuard, write_file_safe};
use crate::core::context::CoreContext;
use crate::core::vault_loader::unlock_vault_if_needed;
use crate::crypto::ExposeSecret;
use crate::crypto::vault::{EncryptedFile, VaultKey};
use crate::engine::EngineError;
use crate::engine::git_transport::GitRunner;
use crate::engine::observer::{
    CommandObserver, NoopObserver, PlanActionKind, PlanDirection, PlanPreviewEntry,
};
use crate::engine::remote::{RemoteRepoUrl, discover_manifests_in_tree, parse_url};

pub const STAGING_CLONE_PREFIX: &str = ".dotler-tmp-clone-";

/// Remote group selector with optional local rename alias (`remote_group[:local_alias]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSelector {
    pub remote_group: String,
    pub local_alias: Option<String>,
}

impl GroupSelector {
    pub fn parse(s: &str) -> Self {
        if let Some((group, alias)) = s.split_once(':') {
            Self {
                remote_group: group.trim().to_string(),
                local_alias: Some(alias.trim().to_string()),
            }
        } else {
            Self {
                remote_group: s.trim().to_string(),
                local_alias: None,
            }
        }
    }
}

/// Summary report returned by `git clone`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloneReport {
    pub repo_url: String,
    pub destination: PathBuf,
    pub cloned_groups: Vec<String>,
}

/// Clones a remote dotler repository using [`NoopObserver`].
#[allow(clippy::too_many_arguments)]
pub fn clone_repo(
    url: &RemoteRepoUrl,
    selectors: &[GroupSelector],
    branch: Option<&str>,
    target_dir: &Path,
    local_config_path: Option<&Path>,
    remote_vault_key: Option<&VaultKey>,
    local_vault_key: Option<&VaultKey>,
    lock: &DotlerLockGuard,
) -> Result<CloneReport, EngineError> {
    let mut noop = NoopObserver;
    clone_repo_with_observer(
        url,
        selectors,
        branch,
        target_dir,
        local_config_path,
        remote_vault_key,
        local_vault_key,
        lock,
        false,
        &mut noop,
    )
}

#[derive(Clone, Copy)]
struct LocalVaultRekeyTarget<'a> {
    config: &'a VaultConfig,
    use_keyring: bool,
    is_interactive: bool,
}

/// Clones a remote dotler repository via staging workspace, optional group selection, and re-keying.
#[allow(clippy::too_many_arguments)]
pub fn clone_repo_with_observer(
    url: &RemoteRepoUrl,
    selectors: &[GroupSelector],
    branch: Option<&str>,
    target_dir: &Path,
    local_config_path: Option<&Path>,
    remote_vault_key: Option<&VaultKey>,
    local_vault_key: Option<&VaultKey>,
    lock: &DotlerLockGuard,
    dry_run: bool,
    observer: &mut dyn CommandObserver,
) -> Result<CloneReport, EngineError> {
    clone_repo_inner(
        url,
        selectors,
        branch,
        target_dir,
        local_config_path,
        remote_vault_key,
        local_vault_key,
        None,
        lock,
        dry_run,
        observer,
    )
}

#[allow(clippy::too_many_arguments)]
fn clone_repo_inner(
    url: &RemoteRepoUrl,
    selectors: &[GroupSelector],
    branch: Option<&str>,
    target_dir: &Path,
    local_config_path: Option<&Path>,
    remote_vault_key: Option<&VaultKey>,
    local_vault_key: Option<&VaultKey>,
    local_vault_target: Option<LocalVaultRekeyTarget<'_>>,
    _lock: &DotlerLockGuard,
    dry_run: bool,
    observer: &mut dyn CommandObserver,
) -> Result<CloneReport, EngineError> {
    if target_dir.exists() && target_dir.read_dir()?.next().is_some() {
        return Err(EngineError::GitError {
            operation: "clone".to_string(),
            message: format!(
                "Destination directory '{}' already exists and is not empty",
                target_dir.display()
            ),
        });
    }

    let validated_repo_entry = if let Some(cfg_path) = local_config_path {
        let home = resolve_home_for_config_path(cfg_path);
        Some(format_home_repo_path(target_dir, &home)?)
    } else {
        None
    };

    let parent = target_dir.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;

    let rand_id: u32 = crate::crypto::random_u32();
    let staging_dir = parent.join(format!("{STAGING_CLONE_PREFIX}{rand_id:08x}"));

    struct AutoCleanup<'a>(&'a Path, bool);
    impl<'a> Drop for AutoCleanup<'a> {
        fn drop(&mut self) {
            if self.1 && self.0.exists() {
                let _ = fs::remove_dir_all(self.0);
            }
        }
    }
    let mut cleanup = AutoCleanup(&staging_dir, true);

    GitRunner::clone_shallow(&url.clone_url, branch, &staging_dir)?;
    let discovered = discover_manifests_in_tree(&staging_dir, url.subpath.as_deref(), &url.raw)?;
    let primary = &discovered[0];
    let repo_config = &primary.config;
    let manifest_dir = &primary.manifest_dir;

    let selected_pairs = resolve_selected_pairs(repo_config, selectors)?;
    let selected_groups: Vec<String> = selected_pairs.iter().map(|(_, eff)| eff.clone()).collect();

    for (remote_name, _) in &selected_pairs {
        for path in repo_config.groups[remote_name].paths.values() {
            validate_path_security(path)?;
        }
    }

    let (preview_entries, clone_files) = build_clone_preview(
        url,
        manifest_dir,
        target_dir,
        &selected_pairs,
        &selected_groups,
    )?;

    let approved = observer.confirm_plan(&preview_entries, dry_run)?;
    if dry_run {
        return Ok(CloneReport {
            repo_url: url.raw.clone(),
            destination: target_dir.to_path_buf(),
            cloned_groups: selected_groups,
        });
    }
    if !approved {
        return Ok(CloneReport {
            repo_url: url.raw.clone(),
            destination: target_dir.to_path_buf(),
            cloned_groups: Vec::new(),
        });
    }

    if !selectors.is_empty() {
        apply_group_pruning_and_aliases(manifest_dir, repo_config, &selected_pairs)?;
    }

    // In-memory re-keying if local vault exists and differs from remote vault.
    if let (Some(r_key), Some(l_key)) = (remote_vault_key, local_vault_key)
        && r_key.vault_id() != l_key.vault_id()
    {
        rekey_cloned_vault_files(manifest_dir, r_key, l_key)?;
    } else if let Some(local_target) = local_vault_target {
        rekey_cloned_manifest_for_local_vault(manifest_dir, repo_config, local_target)?;
    }

    if manifest_dir == &staging_dir {
        fs::rename(&staging_dir, target_dir)?;
        cleanup.1 = false;
    } else {
        if target_dir.exists() {
            let _ = fs::remove_dir(target_dir);
        }
        fs::rename(manifest_dir, target_dir)?;
    }

    let total = clone_files.len();
    for (g_name, g_base, rel, size) in &clone_files {
        observer.on_file_progress(g_name, g_base, rel, Some(*size));
    }
    if total > 0 {
        observer.finish_progress();
    }

    if let Some((cfg_path, repo_entry)) = local_config_path.zip(validated_repo_entry.as_deref()) {
        register_cloned_repo(cfg_path, target_dir, repo_entry)?;
    }

    Ok(CloneReport {
        repo_url: url.raw.clone(),
        destination: target_dir.to_path_buf(),
        cloned_groups: selected_groups,
    })
}

fn resolve_selected_pairs(
    repo_config: &RepoConfig,
    selectors: &[GroupSelector],
) -> Result<Vec<(String, String)>, EngineError> {
    if selectors.is_empty() {
        return Ok(repo_config
            .groups
            .keys()
            .map(|k| (k.clone(), k.clone()))
            .collect());
    }
    for sel in selectors {
        if !repo_config.groups.contains_key(&sel.remote_group) {
            return Err(EngineError::GroupNotFound {
                group: sel.remote_group.clone(),
                available: repo_config.groups.keys().cloned().collect(),
            });
        }
    }
    Ok(selectors
        .iter()
        .map(|s| {
            let effective = s
                .local_alias
                .clone()
                .unwrap_or_else(|| s.remote_group.clone());
            (s.remote_group.clone(), effective)
        })
        .collect())
}

type CloneFileItem = (String, PathBuf, String, u64);

fn build_clone_preview(
    url: &RemoteRepoUrl,
    manifest_dir: &Path,
    target_dir: &Path,
    selected_pairs: &[(String, String)],
    selected_groups: &[String],
) -> Result<(Vec<PlanPreviewEntry>, Vec<CloneFileItem>), EngineError> {
    let mut preview_entries = Vec::new();
    let mut clone_files = Vec::new();

    for (remote_name, effective_name) in selected_pairs {
        let g_dir = manifest_dir.join(remote_name);
        if !g_dir.is_dir() {
            continue;
        }
        for entry in WalkDir::new(&g_dir).min_depth(1) {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }
            let rel = entry
                .path()
                .strip_prefix(&g_dir)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .to_string();
            let is_enc = entry.path().extension().and_then(|s| s.to_str()) == Some("enc");
            let size = fs::metadata(entry.path()).map(|m| m.len()).unwrap_or(0);
            preview_entries.push(PlanPreviewEntry {
                group_name: effective_name.clone(),
                os_path: PathBuf::from(format!("{}/{}/{}", url.raw, remote_name, rel)),
                os_action: PlanActionKind::Okay,
                repo_path: target_dir.join(effective_name).join(&rel),
                repo_action: PlanActionKind::Create,
                direction: if is_enc {
                    PlanDirection::EncryptToRepo
                } else {
                    PlanDirection::PlainToRepo
                },
            });
            clone_files.push((
                effective_name.clone(),
                target_dir.join(effective_name),
                rel,
                size,
            ));
        }
    }

    if preview_entries.is_empty() {
        let fallback_group = selected_groups
            .first()
            .cloned()
            .unwrap_or_else(|| "repo".to_string());
        preview_entries.push(PlanPreviewEntry {
            group_name: fallback_group.clone(),
            os_path: PathBuf::from(format!("{}/dotler.toml", url.raw)),
            os_action: PlanActionKind::Okay,
            repo_path: target_dir.join("dotler.toml"),
            repo_action: PlanActionKind::Create,
            direction: PlanDirection::PlainToRepo,
        });
        clone_files.push((
            fallback_group,
            target_dir.to_path_buf(),
            "dotler.toml".to_string(),
            0,
        ));
    }

    Ok((preview_entries, clone_files))
}

fn apply_group_pruning_and_aliases(
    manifest_dir: &Path,
    repo_config: &RepoConfig,
    selected_pairs: &[(String, String)],
) -> Result<(), EngineError> {
    for remote_group in repo_config.groups.keys() {
        if !selected_pairs.iter().any(|(r, _)| r == remote_group) {
            let unselected_dir = manifest_dir.join(remote_group);
            if unselected_dir.is_dir() {
                let _ = fs::remove_dir_all(&unselected_dir);
            }
        }
    }
    for (remote_name, effective_name) in selected_pairs {
        if remote_name != effective_name {
            let src_dir = manifest_dir.join(remote_name);
            let dst_dir = manifest_dir.join(effective_name);
            if src_dir.is_dir() {
                fs::rename(&src_dir, &dst_dir)?;
            }
        }
    }
    let mut new_groups = BTreeMap::new();
    for (remote_name, effective_name) in selected_pairs {
        if let Some(cfg) = repo_config.groups.get(remote_name) {
            new_groups.insert(effective_name.clone(), cfg.clone());
        }
    }
    let updated_cfg = RepoConfig {
        vault: repo_config.vault.clone(),
        groups: new_groups,
    };
    if let Ok(serialized) = toml::to_string_pretty(&updated_cfg) {
        write_file_safe(&manifest_dir.join("dotler.toml"), serialized.as_bytes())?;
    }
    Ok(())
}

fn rekey_cloned_vault_files(
    manifest_dir: &Path,
    remote_key: &VaultKey,
    local_key: &VaultKey,
) -> Result<(), EngineError> {
    for entry in WalkDir::new(manifest_dir).min_depth(1) {
        let entry = entry?;
        if entry.file_type().is_file()
            && entry.path().extension().and_then(|s| s.to_str()) == Some("enc")
        {
            let enc_bytes = fs::read(entry.path())?;
            let enc_file = EncryptedFile::from_bytes(&enc_bytes)?;
            let decrypted = remote_key.decrypt_file(&enc_file)?;
            let re_encrypted = local_key.encrypt_file(decrypted.expose_secret())?;
            write_file_safe(entry.path(), &re_encrypted.to_bytes())?;
        }
    }
    Ok(())
}

fn has_any_enc_files(manifest_dir: &Path) -> bool {
    WalkDir::new(manifest_dir)
        .min_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
        .any(|e| {
            e.file_type().is_file() && e.path().extension().and_then(|s| s.to_str()) == Some("enc")
        })
}

fn rekey_cloned_manifest_for_local_vault(
    manifest_dir: &Path,
    remote_cfg: &RepoConfig,
    local_target: LocalVaultRekeyTarget<'_>,
) -> Result<(), EngineError> {
    let remote_differs = remote_cfg
        .vault
        .as_ref()
        .is_some_and(|rv| rv.vault_id != local_target.config.vault_id);
    let has_enc = has_any_enc_files(manifest_dir);
    if !has_enc && !remote_differs {
        return Ok(());
    }
    if remote_cfg
        .vault
        .as_ref()
        .is_some_and(|rv| rv.vault_id == local_target.config.vault_id)
    {
        return Ok(());
    }

    if has_enc {
        let local_manifest_stub = RepoConfig {
            vault: Some(local_target.config.clone()),
            ..Default::default()
        };
        let local_key = unlock_vault_if_needed(
            &local_manifest_stub,
            local_target.use_keyring,
            local_target.is_interactive,
            true,
        )?
        .ok_or(EngineError::Config(
            crate::config::ConfigError::MissingVaultConfig,
        ))?;
        let remote_key = unlock_vault_if_needed(
            remote_cfg,
            local_target.use_keyring,
            local_target.is_interactive,
            true,
        )?
        .ok_or(EngineError::Config(
            crate::config::ConfigError::MissingVaultConfig,
        ))?;
        rekey_cloned_vault_files(manifest_dir, &remote_key, &local_key)?;
    }

    let manifest_path = manifest_dir.join("dotler.toml");
    if let Some(ref old_v) = remote_cfg.vault {
        let manifest_str = fs::read_to_string(&manifest_path)?;
        let updated = update_vault_manifest_section(&manifest_str, old_v, local_target.config);
        write_file_safe(&manifest_path, updated.as_bytes())?;
    } else {
        let mut updated_cfg = RepoConfig::load_without_vault_check(&manifest_path)?;
        updated_cfg.vault = Some(local_target.config.clone());
        updated_cfg.save_atomic(&manifest_path)?;
    }
    Ok(())
}

fn register_cloned_repo(
    cfg_path: &Path,
    target_dir: &Path,
    repo_path_entry: &str,
) -> Result<(), EngineError> {
    let mut local_config = if cfg_path.is_file() {
        LocalConfig::load(cfg_path)?
    } else {
        LocalConfig::default()
    };
    let label = target_dir
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    if local_config.default_repo.is_none() {
        local_config.default_repo = Some(label.clone());
    }
    if local_config.default_devices.is_empty() {
        local_config.default_devices.push("default".to_string());
    }
    local_config
        .repos
        .insert(label, repo_path_entry.to_string());
    local_config.save_atomic(cfg_path)?;
    Ok(())
}

/// High-level entry point for `dotler git clone` shared by CLI and MCP.
#[allow(clippy::too_many_arguments)]
pub fn run_git_clone(
    ctx: &CoreContext,
    url_raw: &str,
    selectors: &[GroupSelector],
    branch: Option<&str>,
    target_dir: &Path,
    local_config_path: Option<&Path>,
    lock: &DotlerLockGuard,
    dry_run: bool,
    observer: &mut dyn CommandObserver,
) -> Result<CloneReport, EngineError> {
    let url = parse_url(url_raw)?;
    let resolved_local = if ctx.repo_override.is_some() {
        Some((ctx.resolve_repo()?, ctx.local_config.get()?.use_keyring))
    } else {
        None
    };
    let local_vault_target = resolved_local.as_ref().and_then(|(res, use_keyring)| {
        res.repo_config
            .vault
            .as_ref()
            .map(|vcfg| LocalVaultRekeyTarget {
                config: vcfg,
                use_keyring: *use_keyring,
                is_interactive: ctx.is_interactive,
            })
    });
    clone_repo_inner(
        &url,
        selectors,
        branch,
        target_dir,
        local_config_path,
        None,
        None,
        local_vault_target,
        lock,
        dry_run,
        observer,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::state::DotlerLock;
    use crate::crypto::SecretString;
    use crate::crypto::vault::init_vault;
    use std::process::Command;
    use std::time::Duration;

    fn create_test_bare_repo(
        dotler_toml: &str,
        files: &[(&str, &[u8])],
    ) -> (tempfile::TempDir, String) {
        let tmp = tempfile::tempdir().unwrap();
        let wt = tmp.path().join("wt");
        let bare = tmp.path().join("bare.git");
        fs::create_dir_all(&wt).unwrap();
        let run = |args: &[&str], dir: &Path| {
            let st = Command::new("git")
                .args(args)
                .current_dir(dir)
                .status()
                .unwrap();
            assert!(st.success(), "git {:?} failed", args);
        };
        run(&["init", "-b", "main"], &wt);
        run(&["config", "user.name", "Tester"], &wt);
        run(&["config", "user.email", "test@dotler.dev"], &wt);
        fs::write(wt.join("dotler.toml"), dotler_toml).unwrap();
        for (rel, body) in files {
            let p = wt.join(rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(p, body).unwrap();
        }
        run(&["add", "."], &wt);
        run(&["commit", "-m", "seed"], &wt);
        run(
            &[
                "clone",
                "--bare",
                wt.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            tmp.path(),
        );
        (tmp, format!("file://{}", bare.display()))
    }

    #[test]
    fn group_selector_parse_handles_plain_and_aliased_inputs() {
        assert_eq!(
            GroupSelector::parse("shell"),
            GroupSelector {
                remote_group: "shell".to_string(),
                local_alias: None,
            }
        );
        assert_eq!(
            GroupSelector::parse(" nvim : my-nvim "),
            GroupSelector {
                remote_group: "nvim".to_string(),
                local_alias: Some("my-nvim".to_string()),
            }
        );
    }

    #[test]
    fn clone_with_local_config_rejects_outside_home_before_network() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let dotler_dir = home.join(".config").join("dotler");
        fs::create_dir_all(&dotler_dir).unwrap();
        let cfg_path = dotler_dir.join("config.toml");
        let outside_dest = tmp.path().join("outside").join("cloned");

        let lock = DotlerLock::new(dotler_dir.join("dotler.lock"))
            .acquire(Duration::from_millis(500), Duration::from_millis(10))
            .unwrap();
        let url = parse_url("file:///nonexistent/repo.git").unwrap();

        let err = clone_repo(
            &url,
            &[],
            None,
            &outside_dest,
            Some(&cfg_path),
            None,
            None,
            &lock,
        )
        .unwrap_err();
        assert_eq!(err.error_code(), "CONFIG_ERROR");
        assert!(!outside_dest.exists());
    }

    #[test]
    fn clone_repo_inner_with_local_vault_target_rekeys_enc_and_updates_manifest() {
        let _mock = crate::crypto::keyring::MockKeyringGuard::new();
        unsafe {
            std::env::remove_var(crate::crypto::keyring::PASSPHRASE_ENV_VAR);
        }

        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let dotler_dir = home.join(".config").join("dotler");
        let clone_dest = home.join("cloned-dots");
        fs::create_dir_all(&dotler_dir).unwrap();

        let pass_local = SecretString::new("local-clone-pass-111".to_string());
        let pass_remote = SecretString::new("remote-clone-pass-222".to_string());
        let (vcfg_local, vkey_local, _) = init_vault(&pass_local).unwrap();
        let (vcfg_remote, vkey_remote, _) = init_vault(&pass_remote).unwrap();

        let cfg_path = dotler_dir.join("config.toml");
        crate::crypto::keyring::OsKeyring::set_for_vault(&vcfg_local.vault_id, &pass_local)
            .unwrap();
        crate::crypto::keyring::OsKeyring::set_for_vault(&vcfg_remote.vault_id, &pass_remote)
            .unwrap();

        let enc_payload = vkey_remote
            .encrypt_file(b"TOKEN=from_remote\n")
            .unwrap()
            .to_bytes();
        let remote_toml = format!(
            "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n\n[sec]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nos-bsd = \"~\"\nfiles = \".token enc\"\n",
            vcfg_remote.vault_id, vcfg_remote.password_slot, vcfg_remote.recovery_slot
        );
        let (_git_tmp, bare_url) =
            create_test_bare_repo(&remote_toml, &[("sec/.token.enc", &enc_payload)]);

        let lock = DotlerLock::new(dotler_dir.join("dotler.lock"))
            .acquire(Duration::from_millis(500), Duration::from_millis(10))
            .unwrap();
        let url = parse_url(&bare_url).unwrap();
        let mut obs = NoopObserver;
        let rep = clone_repo_inner(
            &url,
            &[],
            None,
            &clone_dest,
            Some(&cfg_path),
            None,
            None,
            Some(LocalVaultRekeyTarget {
                config: &vcfg_local,
                use_keyring: true,
                is_interactive: false,
            }),
            &lock,
            false,
            &mut obs,
        )
        .unwrap();
        assert_eq!(rep.destination, clone_dest);

        let cloned_enc =
            EncryptedFile::from_bytes(&fs::read(clone_dest.join("sec/.token.enc")).unwrap())
                .unwrap();
        assert_eq!(cloned_enc.vault_id, vkey_local.vault_id_bytes());
        assert_eq!(
            vkey_local
                .decrypt_file(&cloned_enc)
                .unwrap()
                .expose_secret(),
            b"TOKEN=from_remote\n"
        );
        let cloned_manifest = RepoConfig::load(&clone_dest.join("dotler.toml")).unwrap();
        assert_eq!(cloned_manifest.vault.unwrap().vault_id, vcfg_local.vault_id);
        let reloaded_cfg = LocalConfig::load(&cfg_path).unwrap();
        assert_eq!(
            reloaded_cfg.repos.get("cloned-dots").map(String::as_str),
            Some("~/cloned-dots")
        );
    }
}

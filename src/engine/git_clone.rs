//! Remote Git staging clone, group selection/aliasing, and vault re-keying (`git clone`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::local::{LocalConfig, WalkDir};
use crate::config::repo::{RepoConfig, validate_path_security};
use crate::config::state::{DotlerLockGuard, write_file_safe};
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

    let (preview_entries, clone_files) =
        build_clone_preview(url, manifest_dir, target_dir, &selected_pairs, &selected_groups)?;

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

    if let Some(cfg_path) = local_config_path {
        register_cloned_repo(cfg_path, target_dir)?;
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
            clone_files.push((effective_name.clone(), target_dir.join(effective_name), rel, size));
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
        clone_files.push((fallback_group, target_dir.to_path_buf(), "dotler.toml".to_string(), 0));
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

fn register_cloned_repo(cfg_path: &Path, target_dir: &Path) -> Result<(), EngineError> {
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
    let home = std::env::home_dir().unwrap_or_else(|| PathBuf::from("~"));
    let repo_path_entry = if let Ok(rel) = target_dir.strip_prefix(&home) {
        if rel.as_os_str().is_empty() {
            "~".to_string()
        } else {
            format!("~/{}", rel.display())
        }
    } else {
        format!(
            "~/{}",
            target_dir
                .file_name()
                .map(|f| f.to_string_lossy())
                .unwrap_or_default()
        )
    };
    if local_config.default_repo.is_none() {
        local_config.default_repo = Some(label.clone());
    }
    if local_config.default_devices.is_empty() {
        local_config.default_devices.push("default".to_string());
    }
    local_config.repos.insert(label, repo_path_entry);
    local_config.save_atomic(cfg_path)?;
    Ok(())
}

/// High-level entry point for `dotler git clone` shared by CLI and MCP.
#[allow(clippy::too_many_arguments)]
pub fn run_git_clone(
    url_raw: &str,
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
    let url = parse_url(url_raw)?;
    clone_repo_with_observer(
        &url,
        selectors,
        branch,
        target_dir,
        local_config_path,
        remote_vault_key,
        local_vault_key,
        lock,
        dry_run,
        observer,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
